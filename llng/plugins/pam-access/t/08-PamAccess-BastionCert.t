use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);
use Time::Local qw(timelocal);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

# This endpoint signs real SSH certificates by forking ssh-keygen, and needs
# openssl to mint the CA key — skip cleanly where they are unavailable.
system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';
my ( $op, $res );

# --- Generate an SSH CA keypair (PEM) for the ssh-ca plugin -------------------
my ( $ca_private_key, $ca_public_key );
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $tmpdir/ca.key 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl key generation failed";
    system(
        "openssl rsa -in $tmpdir/ca.key -pubout -out $tmpdir/ca.pub 2>/dev/null")
      == 0
      or plan skip_all => "openssl pubkey extraction failed";
    local $/;
    open my $fh, '<', "$tmpdir/ca.key" or die;
    $ca_private_key = <$fh>;
    close $fh;
    open $fh, '<', "$tmpdir/ca.pub" or die;
    $ca_public_key = <$fh>;
    close $fh;
}

# --- Generate an ephemeral user keypair (what a bastion would mint) -----------
my $eph_pubkey;
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $tmpdir/eph -N '' -q -C ephemeral-hop") == 0
      or plan skip_all => "ssh-keygen key generation failed";
    open my $fh, '<', "$tmpdir/eph.pub" or die;
    $eph_pubkey = <$fh>;
    close $fh;
    chomp $eph_pubkey;
}

my $krl = tempdir( CLEANUP => 1 ) . "/revoked_keys";

# --- OP with pam-access + ssh-ca (cert vouching) -----------------------------
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),

                # Add SSHCA on top of base_config's customPlugins.
                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::SSHCA',

                # ssh-ca CA key
                sshCaKeyRef  => 'ssh-ca',
                sshCaKrlPath => $krl,
                keys         => {
                    'ssh-ca' => {
                        keyPublic  => $ca_public_key,
                        keyPrivate => $ca_private_key,
                        keyComment => 'test ssh ca',
                    }
                },

                # 'default' is deliberately NOT a bastion group. An enrolled
                # server resolves to 'default' in legacy mode (no per-host
                # server_group in the device-grant session — the realistic case
                # with one project-wide client_id), so this proves
                # /pam/bastion-cert does not gate on the caller's group: the
                # voucher (minted only when the caller authorizes with a real
                # bastion group) is the sole security control.
                pamAccessBastionGroups => 'bastion',
                pamAccessSshRules      => { default => '1', bastion => '1' },
                # Pin issued certs to the bastion IP (off by default); the
                # "pin disabled" block below overrides this back to 0.
                pamAccessBastionCertPinSourceAddress => 1,
                # 90s (not a multiple of 60) so the issued cert can only
                # come from the "+90s" $opts override, not the legacy
                # minute-granularity argument.
                pamAccessBastionCertTtl => 90,

                # Deliberately invalid: minting must fall back to the 12h
                # default instead of issuing dead vouchers.
                pamAccessBastionVoucherTtl => 'twelve-hours',
            }
        }
    ),
    'OP with pam-access + ssh-ca cert vouching'
);

# ============================================================================
# Caller-gate error cases (no enrollment needed)
# ============================================================================
my $cert_body = to_json(
    { user => 'french', target_host => 'b', public_key => $eph_pubkey } );

# Without Bearer token
ok(
    $res = $op->_post(
        '/pam/bastion-cert',
        IO::String->new($cert_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($cert_body),
    ),
    'POST /pam/bastion-cert without Bearer'
);
is( $res->[0], 401, '  -> 401 without Bearer' );

# With invalid Bearer token
ok(
    $res = $op->_post(
        '/pam/bastion-cert',
        IO::String->new($cert_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($cert_body),
        custom => { HTTP_AUTHORIZATION => "Bearer invalid_xyz" },
    ),
    'POST /pam/bastion-cert with invalid Bearer'
);
is( $res->[0], 401, '  -> 401 with invalid Bearer' );

# ============================================================================
# Enroll a bastion, then run the real flow
# ============================================================================
my $id = $op->login('french');
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got bastion server token' );

# Helper: POST a JSON body to a pam endpoint with the bastion Bearer.
sub bastion_post {
    my ( $path, $hash, %custom ) = @_;
    my $body = to_json($hash);
    return $op->_post(
        $path,
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token", %custom },
    );
}

# --- /pam/authorize mints a (bastion_id, user) voucher -----------------------
$res = bastion_post( '/pam/authorize',
    { user => 'french', server_group => 'bastion', host => 'b1', service => 'ssh' } );
is( $res->[0], 200, '/pam/authorize 200' );
my $authz = from_json( $res->[2]->[0] );
ok( $authz->{authorized}, '  -> authorized' );
my $voucher = $authz->{bastion_voucher};
ok( $voucher, '  -> bastion_voucher present' );

# The bastion identifies itself by its device-grant client_id here (no
# organization ownership is configured), and that is the bastion_id the
# voucher is keyed on.
my $BASTION_ID = 'pam-access';

# No fingerprint was supplied, so nothing binds this voucher to the user's SSO
# certificate lifetime. It used to get the full pamAccessBastionVoucherTtl (12h
# by default), which made "revoking the SSO invalidates the voucher" depend on
# an optional binding being in play. Unbound vouchers are now capped by
# pamAccessBastionVoucherUnboundTtl, 15 minutes by default (issue #55).
cmp_ok( $authz->{bastion_voucher_expires_in},
    '<=', 900, '  -> unbound voucher capped at the short TTL' );
cmp_ok( $authz->{bastion_voucher_expires_in},
    '>', 0, '  -> and is still usable' );

# pamAccessRequireFingerprint refuses the unbound case outright instead.
# The refusal carries its OWN audit code, not the malformed one: a SIEM
# telling "a caller sent garbage" apart from "a caller has not rolled out the
# fingerprint spool yet" should not have to parse the payload's `reason`.
{
    my $conf = $op->p->conf;
    local $conf->{pamAccessRequireFingerprint} = 1;

    my @audit;
    no warnings 'redefine';
    my $orig = \&Lemonldap::NG::Common::PSGI::auditLog;
    local *Lemonldap::NG::Common::PSGI::auditLog = sub {
        my ( $self, $req, %info ) = @_;
        push @audit, \%info;
        return $orig->( $self, $req, %info );
    };
    use warnings 'redefine';

    my $r = bastion_post( '/pam/authorize',
        { user => 'french', server_group => 'bastion', host => 'b1',
            service => 'ssh' } );
    is( $r->[0], 400, '  -> requireFingerprint: no fingerprint is a 400' );
    like( from_json( $r->[2]->[0] )->{error},
        qr/fingerprint required/i, '  -> and says so' );

    my ($ev) =
      grep { ( $_->{reason} // '' ) eq 'fingerprint_required' } @audit;
    ok( $ev, '  -> and is audited' );
    is( $ev && $ev->{code},
        'PAM_AUTHZ_SSH_FP_REQUIRED',
        '  -> under its own code, not the malformed one' );
}

# ============================================================================
# Body-validation cases (with a valid Bearer)
# ============================================================================

# Missing user
$res = bastion_post( '/pam/bastion-cert',
    { target_host => 'b', public_key => $eph_pubkey, voucher => $voucher } );
is( $res->[0], 400, 'bastion-cert without user -> 400' );

# Missing public_key
$res = bastion_post( '/pam/bastion-cert',
    { user => 'french', target_host => 'b', voucher => $voucher } );
is( $res->[0], 400, 'bastion-cert without public_key -> 400' );

# Missing voucher
$res = bastion_post( '/pam/bastion-cert',
    { user => 'french', target_host => 'b', public_key => $eph_pubkey } );
is( $res->[0], 400, 'bastion-cert without voucher -> 400' );

# Malformed public key
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'b',
        public_key  => 'not-a-key',
        voucher     => $voucher
    }
);
is( $res->[0], 400, 'bastion-cert with malformed public_key -> 400' );

# ============================================================================
# SECURITY: voucher binding
# ============================================================================

# Wrong voucher value
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'b',
        public_key  => $eph_pubkey,
        voucher     => 'deadbeef-0000'
    }
);
is( $res->[0], 403, 'wrong voucher -> 403' );
is( from_json( $res->[2]->[0] )->{reason},
    'voucher_mismatch', '  -> reason voucher_mismatch' );

# **KEY TEST**: a user the bastion never authorized (no voucher of their own)
# cannot get a cert, even reusing another user's voucher value.
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'dwho',
        target_host => 'b',
        public_key  => $eph_pubkey,
        voucher     => $voucher
    }
);
is( $res->[0], 403, 'cert for non-vouched user (dwho) -> 403' );
is( from_json( $res->[2]->[0] )->{error},
    'voucher_rejected', '  -> voucher_rejected' );

# ============================================================================
# Successful issuance + cert contents
# ============================================================================
my $t_sign = time;
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user         => 'french',
        target_host  => 'backend1.op.com',
        target_group => 'production',
        public_key   => $eph_pubkey,
        voucher      => $voucher,
    }
);
is( $res->[0], 200, 'valid voucher -> 200 cert issued' );
my $certresp = from_json( $res->[2]->[0] );
ok( $certresp->{certificate}, '  -> certificate returned' );
is( $certresp->{expires_in}, 90, '  -> expires_in is the configured TTL' );
is(
    $certresp->{key_id},
    'bastion=pam-access;user=french;target=backend1.op.com',
    '  -> key_id encodes bastion/user/target'
);

# Inspect the signed certificate with ssh-keygen -L
SKIP: {
    skip "no certificate to inspect", 6 unless $certresp->{certificate};
    my $tmpdir = tempdir( CLEANUP => 1 );
    open my $fh, '>', "$tmpdir/c-cert.pub" or die;
    print $fh $certresp->{certificate};
    close $fh;
    my $L = `ssh-keygen -L -f $tmpdir/c-cert.pub 2>&1`;
    like( $L, qr/Type:\s+\S+-cert-v01\@openssh\.com user certificate/,
        '  -> is a user certificate' );
    like( $L, qr/Principals:\s*\n\s+french\b/, '  -> principal is french' );
    like( $L, qr/Key ID: "bastion=pam-access;user=french;target=backend1\.op\.com"/,
        '  -> key-id present in cert' );

    # The _signSshKey $opts contract: source-address pins the cert to the
    # vouching bastion's IP (test requests come from 127.0.0.1)...
    like( $L, qr/source-address\s+127\.0\.0\.1/,
        '  -> source-address critical option pins the bastion IP' );

    # ...and validity carries the sub-minute "+90s" $opts override. OpenSSH
    # backdates the start by a 60s clock-skew allowance rounded down to the
    # minute, so only the end timestamp is assertable: it must land ~90s
    # after the signing request (the legacy +2m path would give ~120s).
    my ( $from, $to ) = $L =~ /Valid:\s+from\s+(\S+)\s+to\s+(\S+)/;
    ok( $from && $to, '  -> validity window present' );
    my $epoch = sub {
        my @f = $_[0] =~ /(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)/;
        return @f ? timelocal( @f[ 5, 4, 3 ], $f[2], $f[1] - 1, $f[0] ) : 0;
    };
    my $end = $epoch->($to) - $t_sign;
    ok( $end >= 85 && $end <= 95,
        "  -> cert expires ~90s after signing (got ${end}s)" );
}

# ============================================================================
# The ephemeral cert's fingerprint is registered (under its own per-fingerprint
# key, not in _sshCerts) so the backend's /pam/authorize SSH-fingerprint binding
# accepts the vouched hop (otherwise it is denied as "fingerprint not-found").
# ============================================================================
{
    # The ephemeral cert was signed from $eph_pubkey; its public-key fingerprint
    # is what the backend forwards and what we must have registered.
    my $sshca = $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'};
    my $eph_fp = $sshca->_sshKeyFingerprint($eph_pubkey);
    ok( $eph_fp, 'computed ephemeral key fingerprint' );

    my $ps  = $op->p->getPersistentSession('french');
    my $raw = $ps->data->{ "_pamEphCert::" . $eph_fp };
    ok( $raw, 'ephemeral hop cert registered under its per-fingerprint key' );
    my $sshCerts =
      $ps->data->{_sshCerts} ? from_json( $ps->data->{_sshCerts} ) : [];
    ok( !( grep { ( $_->{fingerprint} || '' ) eq $eph_fp } @$sshCerts ),
        '  -> NOT mixed into the ssh-ca _sshCerts list' );
    my $rec = $raw ? from_json($raw) : {};
    ok( $rec->{expires_at} && $rec->{expires_at} <= time() + 90 + 5,
        '  -> entry is short-lived (cert TTL)' );

    # Integration: the backend's /pam/authorize with that fingerprint is now
    # authorized (previously denied as fingerprint not-found). 'bastion' is a
    # real bastion group, so this mints a fresh voucher — capture it so the
    # voucher-reuse tests below keep working.
    $res = bastion_post(
        '/pam/authorize',
        {
            user         => 'french',
            server_group => 'bastion',
            host         => 'backend1.op.com',
            service      => 'ssh',
            fingerprint  => $eph_fp,
        }
    );
    is( $res->[0], 200, 'POST /pam/authorize with ephemeral fp -> 200' );
    my $a = from_json( $res->[2]->[0] );
    ok( $a->{authorized}, '  -> authorized (fp binding satisfied)' );
    $voucher = $a->{bastion_voucher} if $a->{bastion_voucher};

    # An ephemeral fingerprint that was never issued is still rejected.
    $res = bastion_post(
        '/pam/authorize',
        {
            user         => 'french',
            server_group => 'bastion',
            host         => 'backend1.op.com',
            service      => 'ssh',
            fingerprint  => 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }
    );
    ok( !from_json( $res->[2]->[0] )->{authorized},
        'POST /pam/authorize with an unknown fp -> denied (binding intact)' );
}

# ============================================================================
# Binding window outlives the hop cert's own (short) validity. Regression for
# "sudo fails a couple of minutes into a long backend SSH session": the SSH
# cert's expires_at lapses quickly, but a still-open session must keep
# validating its fingerprint until binding_expires_at. _checkSshFingerprint
# must gate on binding_expires_at, not expires_at — while still rejecting once
# the binding window is closed.
# ============================================================================
{
    my $pam =
      $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'};
    my $sshca =
      $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'};
    my $eph_fp = $sshca->_sshKeyFingerprint($eph_pubkey);
    my $key    = "_pamEphCert::" . $eph_fp;

    my $ps  = $op->p->getPersistentSession('french');
    my $rec = from_json( $ps->data->{$key} );
    ok(
        $rec->{binding_expires_at}
          && $rec->{binding_expires_at} > $rec->{expires_at},
        'binding_expires_at is set and outlives the cert expires_at'
    );

    # Long-open session: the hop cert's validity has lapsed, binding still open.
    $rec->{expires_at}         = time() - 10;
    $rec->{binding_expires_at} = time() + 3600;
    $ps->update( { $key => to_json($rec) } );
    ok( $pam->_checkSshFingerprint( 'french', $eph_fp )->{ok},
        'cert expired but binding window open -> fingerprint accepted' );

    # Binding window closed too -> rejected (falls through to _sshCerts).
    $ps  = $op->p->getPersistentSession('french');
    $rec = from_json( $ps->data->{$key} );
    $rec->{binding_expires_at} = time() - 10;
    $ps->update( { $key => to_json($rec) } );
    ok( !$pam->_checkSshFingerprint( 'french', $eph_fp )->{ok},
        'binding window closed -> fingerprint rejected' );

    # Restore a healthy record so the voucher tests below are unaffected.
    $ps  = $op->p->getPersistentSession('french');
    $rec = from_json( $ps->data->{$key} );
    $rec->{expires_at}         = time() + 90;
    $rec->{binding_expires_at} = time() + 86400;
    $ps->update( { $key => to_json($rec) } );
}

# Voucher is REUSABLE (not consumed) -> supports multi-hop / scp host1: host2:
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'backend2.op.com',
        public_key  => $eph_pubkey,
        voucher     => $voucher,
    }
);
is( $res->[0], 200, 'same voucher reused for a second hop -> 200' );

# ============================================================================
# Concurrent sessions: a user routinely holds several SSH logins on the same
# bastion at once. The voucher is keyed per (bastion_id, user), so a second
# login's /pam/authorize must REUSE the existing nonce, not rotate it -- else
# the first session's already-exported voucher would start failing with
# voucher_mismatch ("works only from the most recent login").
{
    $res = bastion_post( '/pam/authorize',
        { user => 'french', server_group => 'bastion', host => 'b1', service => 'sshd' } );
    is( $res->[0], 200, 'second concurrent login /pam/authorize -> 200' );
    my $v2 = from_json( $res->[2]->[0] )->{bastion_voucher};
    is( $v2, $voucher, '  -> reuses the same voucher nonce (no rotation)' );

    # And a sudo elevation must not mint/rotate the voucher at all.
    $res = bastion_post( '/pam/authorize',
        { user => 'french', server_group => 'bastion', host => 'b1', service => 'sudo' } );
    is( $res->[0], 200, 'sudo /pam/authorize -> 200' );
    my $a = from_json( $res->[2]->[0] );
    ok( !exists $a->{bastion_voucher},
        '  -> sudo does not mint a voucher' );

    # The original login voucher is still valid after both -> not rotated.
    $res = bastion_post(
        '/pam/bastion-cert',
        {
            user        => 'french',
            target_host => 'backend9.op.com',
            public_key  => $eph_pubkey,
            voucher     => $voucher,
        }
    );
    is( $res->[0], 200,
        'login voucher still valid after a concurrent login + sudo -> 200' );
}

# ============================================================================
# pamAccessBastionCertPinSourceAddress = 0 drops the source-address pin
# (for deployments where the IP LLNG observes is not the bastion's SSH egress
# address: portal behind a reverse proxy, multi-homed bastion, NAT, ...).
# ============================================================================
SKIP: {
    skip "no certificate to inspect", 2 unless $certresp->{certificate};
    my $conf = $op->p->conf;
    local $conf->{pamAccessBastionCertPinSourceAddress} = 0;
    $res = bastion_post(
        '/pam/bastion-cert',
        {
            user        => 'french',
            target_host => 'backend3.op.com',
            public_key  => $eph_pubkey,
            voucher     => $voucher,
        }
    );
    is( $res->[0], 200, 'pin disabled -> 200 cert still issued' );
    my $nc = from_json( $res->[2]->[0] );
    my $tmpdir = tempdir( CLEANUP => 1 );
    open my $fh, '>', "$tmpdir/n-cert.pub" or die;
    print $fh $nc->{certificate};
    close $fh;
    my $L = `ssh-keygen -L -f "$tmpdir/n-cert.pub" 2>&1`;
    unlike( $L, qr/source-address/,
        '  -> no source-address critical option when pin disabled' );
}

# ============================================================================
# The pin is requested but cannot be applied -> refuse (issue #56)
#
# REMOTE_ADDR can be absent or empty behind some FastCGI and socket
# front-ends. Minting an unpinned certificate there used to be silent: the
# cert was indistinguishable from a pinned one and the audit record simply
# omitted the field. The option is opt-in, so an operator who set it asked for
# the guarantee.
# ============================================================================
{
    $res = bastion_post(
        '/pam/bastion-cert',
        {
            user        => 'french',
            target_host => 'backend4.op.com',
            public_key  => $eph_pubkey,
            voucher     => $voucher,
        },
        REMOTE_ADDR => '',
    );
    is( $res->[0], 403, 'unusable source address with the pin on -> 403' );
    like(
        from_json( $res->[2]->[0] )->{error},
        qr/Source address pin/,
        '  -> and says why'
    );

    # ... while the same request succeeds when the pin is not requested
    my $conf = $op->p->conf;
    local $conf->{pamAccessBastionCertPinSourceAddress} = 0;
    $res = bastion_post(
        '/pam/bastion-cert',
        {
            user        => 'french',
            target_host => 'backend4.op.com',
            public_key  => $eph_pubkey,
            voucher     => $voucher,
        },
        REMOTE_ADDR => '',
    );
    is( $res->[0], 200, 'pin off: the same request is served' );
}

# ============================================================================
# Pre-upgrade sessions still carry the shared _pamBastionVouchers map (#54):
# it must keep working, and the next mint must drain it into per-bastion keys.
# ============================================================================
{
    my $pfx = $Lemonldap::NG::Portal::Plugins::PamAccess::VOUCHER_PREFIX;
    my $ps  = $op->p->getPersistentSession('french');

    # Move every per-key voucher back into the legacy map.
    my ( %legacy, %upd );
    for my $k ( keys %{ $ps->data } ) {
        next unless index( $k, $pfx ) == 0;
        $legacy{ substr( $k, length $pfx ) } =
          from_json( $ps->data->{$k} );
        $upd{$k} = undef;
    }
    $ps->update( { %upd, _pamBastionVouchers => to_json( \%legacy ) } );

    my $r = bastion_post(
        '/pam/bastion-cert',
        {
            user        => 'french',
            target_host => 'legacy.op.com',
            public_key  => $eph_pubkey,
            voucher     => $voucher,
        }
    );
    is( $r->[0], 200, 'legacy voucher map is still honoured' );

    # A fresh /pam/authorize republishes it per key and drops the map.
    $r = bastion_post( '/pam/authorize',
        { user => 'french', server_group => 'bastion', host => 'b1',
            service => 'ssh' } );
    is( $r->[0], 200, '  -> re-authorize 200' );
    is( from_json( $r->[2]->[0] )->{bastion_voucher},
        $voucher, '  -> the legacy nonce is reused, not rotated' );

    # The mint does NOT touch either pre-upgrade shape. A portal cluster is
    # upgraded node by node, and clearing a key an older node still mints into
    # would hand that node's users a nonce their shell does not have.
    my $after = $op->p->getPersistentSession('french');
    ok( defined $after->data->{_pamBastionVouchers},
        '  -> the pre-upgrade map is read, not rewritten' );
    ok( !( grep { index( $_, $pfx ) == 0 } keys %{ $after->data } ),
        '  -> and no per-bastion key is written either' );

    # It landed in its own record instead.
    my $rec = pam_lib::voucher_session( $op, 'french', $BASTION_ID );
    is( $rec->data->{nonce}, $voucher,
        '  -> the voucher now lives in its own session record' );
    is( $rec->data->{_session_kind}, 'PAMVOUCHER', '  -> kind PAMVOUCHER' );
}

# ============================================================================
# Expired voucher -> 403 voucher_expired (client tells user to reconnect)
# ============================================================================
{
    my $rec = pam_lib::voucher_session( $op, 'french', $BASTION_ID );
    ok( $rec->data->{nonce}, 'the voucher has its own record (issue #54)' );
    $rec->update( { exp => time - 10 } );
}
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'b',
        public_key  => $eph_pubkey,
        voucher     => $voucher,
    }
);
is( $res->[0], 403, 'expired voucher -> 403' );
is( from_json( $res->[2]->[0] )->{reason},
    'voucher_expired', '  -> reason voucher_expired' );

# ============================================================================
# Corrupted pre-upgrade voucher -> 500 (internal failure, not an authz denial)
# ============================================================================
{
    # Corruption is only reachable through a pre-upgrade value: the record
    # stores its fields separately, so there is no blob left to mangle. Drop
    # the record so the legacy read runs, then break what it reads.
    pam_lib::voucher_session( $op, 'french', $BASTION_ID )->remove;
    my $ps  = $op->p->getPersistentSession('french');
    my $pfx = $Lemonldap::NG::Portal::Plugins::PamAccess::VOUCHER_PREFIX;
    $ps->update( { $pfx . $BASTION_ID => 'not-json{' } );
}
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'b',
        public_key  => $eph_pubkey,
        voucher     => $voucher,
    }
);
is( $res->[0], 500, 'corrupted pre-upgrade voucher -> 500' );
{
    my $err = from_json( $res->[2]->[0] );
    is( $err->{error},  'voucher_check_failed', '  -> voucher_check_failed' );
    is( $err->{reason}, 'voucher_corrupted',    '  -> reason voucher_corrupted' );
}

done_testing();
