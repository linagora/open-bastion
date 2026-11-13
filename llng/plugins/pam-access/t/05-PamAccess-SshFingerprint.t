use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    require 't/pam-lib.pm';

    use File::Find;
    use File::Copy;
    use File::Path qw(make_path);
    use FindBin;

    my $plugins_root = "$FindBin::Bin/../../";
    for my $plugin (qw(oidc-device-authorization pam-access ssh-ca)) {
        my $tpl_dir = "$plugins_root/$plugin/portal-templates";
        next unless -d $tpl_dir;
        find(
            {
                wanted => sub {
                    return unless -f $_ && /\.tpl$/;
                    my $rel = $File::Find::name;
                    $rel =~ s{^\Q$tpl_dir/\E}{};
                    my $dst = "site/templates/$rel";
                    make_path( $dst =~ s{/[^/]+$}{}r );
                    File::Copy::copy( $File::Find::name, $dst );
                },
                no_chdir => 1,
            },
            $tpl_dir
        );
    }
}

# Need ssh-keygen + openssl to sign real certificates
system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';

# SSH CA keys (RSA PEM — directly usable by ssh-keygen -s)
my ( $ca_priv, $ca_pub );
{
    my $t = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $t/ca.key 2>/dev/null"
    ) == 0 or plan skip_all => "openssl genrsa failed";
    system("openssl rsa -in $t/ca.key -pubout -out $t/ca.pub 2>/dev/null") == 0
      or plan skip_all => "openssl rsa -pubout failed";
    local $/;
    open my $fh, '<', "$t/ca.key" or die;
    $ca_priv = <$fh>;
    close $fh;
    open $fh, '<', "$t/ca.pub" or die;
    $ca_pub = <$fh>;
    close $fh;
}

# User SSH key + fingerprint
my ( $user_pub, $user_fp );
{
    my $t = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $t/uk -N '' -q -C test-host") == 0
      or plan skip_all => "ssh-keygen user key failed";
    open my $fh, '<', "$t/uk.pub" or die;
    $user_pub = <$fh>;
    close $fh;
    chomp $user_pub;
    my $fp_line = `ssh-keygen -l -E sha256 -f $t/uk.pub`;
    ($user_fp) = $fp_line =~ /\b(SHA256:\S+)/;
}

my $tmpdir  = tempdir( CLEANUP => 1 );
my $krlPath = "$tmpdir/krl";

my ( $op, $res );
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel                        => $debug,
                domain                          => 'op.com',
                portal                          => 'http://auth.op.com',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                issuerDBOpenIDConnectActivation => 1,
                issuerDBOpenIDConnectRule       => '$uid eq "french"',
                customPlugins                   =>
                  '::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::SSHCA',
                oidcRPMetaDataExportedVars      => {
                    'pam-access' => {
                        email  => 'mail',
                        name   => 'cn',
                        groups => 'groups',
                    }
                },
                oidcServiceMetaDataAuthorizeURI       => 'authorize',
                oidcServiceMetaDataCheckSessionURI    => 'check_session',
                oidcServiceMetaDataJWKSURI            => 'jwks',
                oidcServiceMetaDataEndSessionURI      => 'logout',
                oidcServiceMetaDataRegistrationURI    => 'register',
                oidcServiceMetaDataTokenURI           => 'token',
                oidcServiceMetaDataUserInfoURI        => 'userinfo',
                oidcServiceMetaDataIntrospectionURI   => 'introspect',
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcRPMetaDataOptions                 => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    }
                },
                oidcRPMetaDataScopeRules => {
                    'pam-access' => {
                        pam          => '1',
                        'pam:server' => '1',
                    }
                },
                oidcOPMetaDataOptions    => {},
                oidcOPMetaDataJSON       => {},
                oidcOPMetaDataJWKS       => {},
                oidcServicePrivateKeySig => oidc_key_op_private_sig(),
                oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
                pamAccessActivation      => 1,
                pamAccessTokenDuration   => 600,
                pamAccessMaxDuration     => 3600,
                pamAccessRp              => 'pam-access',
                pamAccessSshRules        => { default => '1' },
                pamAccessSudoRules       => { default => '1' },
                sshCaKeyRef              => 'sshca',
                keys                     => {
                    sshca => { keyPrivate => $ca_priv, keyPublic => $ca_pub },
                },
                sshCaKrlPath          => $krlPath,
                sshCaCertMaxValidity  => 30,
                sshCaPrincipalSources => '$uid',
            }
        }
    ),
    'OP with PamAccess+SSHCA initialized'
);

# ------------------------------------------------------------------
# Authenticate and sign an SSH certificate
# ------------------------------------------------------------------

my $query = 'user=french&password=french';
ok(
    $res = $op->_post(
        '/',
        IO::String->new($query),
        accept => 'text/html',
        length => length($query),
    ),
    'Login'
);
my $sid = expectCookie($res);

my $signBody = to_json(
    {
        public_key    => $user_pub,
        validity_days => 1,
        label         => 'my-host',
    }
);
ok(
    $res = $op->_post(
        '/ssh/sign',
        IO::String->new($signBody),
        cookie => "lemonldap=$sid",
        type   => 'application/json',
        length => length($signBody),
    ),
    'Sign SSH key'
);
my $json = expectJSON($res);
is( $json->{fingerprint}, $user_fp, 'Signed cert has expected fingerprint' );
count(1);

# ------------------------------------------------------------------
# Obtain a PAM user token and a server Bearer token
# ------------------------------------------------------------------

sub _new_pam_token {
    my $q = 'duration=300';
    my $r = $op->_post(
        '/pam',
        IO::String->new($q),
        accept => 'application/json',
        cookie => "lemonldap=$sid",
        length => length($q),
    );
    return expectJSON($r)->{token};
}
my $user_token = _new_pam_token();
ok( $user_token, 'Got PAM user token' );
count(1);

my $server_token = pam_lib::enroll_server( $op, $sid );
ok( $server_token, 'Got server Bearer token' );
count(1);

sub _verify {
    my ( $token, $fp ) = @_;
    my $body = to_json(
        { token => $token, ( defined $fp ? ( fingerprint => $fp ) : () ) } );
    return $op->_post(
        '/pam/verify',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
}

# ------------------------------------------------------------------
# Case 1: no fingerprint → plain verify still works (backward compat)
# ------------------------------------------------------------------

$res  = _verify( $user_token, undef );
$json = expectJSON($res);
ok( $json->{valid}, 'verify without fingerprint succeeds' );
is( $json->{user}, 'french', 'Correct user' );
count(2);

# ------------------------------------------------------------------
# Case 2: matching fingerprint → accepted, attrs expose cert info
# ------------------------------------------------------------------

$user_token = _new_pam_token();
$res  = _verify( $user_token, $user_fp );
$json = expectJSON($res);
ok( $json->{valid}, 'verify with matching fingerprint succeeds' );
is( $json->{attrs}->{ssh_cert_label}, 'my-host', 'Label exposed' );
ok( defined $json->{attrs}->{ssh_cert_serial}, 'Serial exposed' );
count(3);

# ------------------------------------------------------------------
# Case 2b: malformed fingerprint → 400
# ------------------------------------------------------------------

$user_token = _new_pam_token();
$res        = _verify( $user_token, 'not-a-fingerprint' );
is( $res->[0], 400, 'verify with malformed fingerprint returns 400' );
$json = JSON::from_json( $res->[2]->[0] );
ok( !$json->{valid}, 'Malformed fingerprint response is not valid' );
like( $json->{error}, qr/fingerprint/i, 'Error mentions fingerprint' );
count(3);

# ------------------------------------------------------------------
# Case 2c: pamAccessRequireFingerprint refuses the unbound call, and the
# refusal keeps /pam/verify's body shape (valid => false), issue #55.
# ------------------------------------------------------------------

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

    $user_token = _new_pam_token();
    $res        = _verify( $user_token, undef );
    is( $res->[0], 400, 'verify without fingerprint is a 400 when required' );
    $json = JSON::from_json( $res->[2]->[0] );
    ok( exists $json->{valid} && !$json->{valid},
        'requireFingerprint refusal keeps the verify body shape' );
    like( $json->{error}, qr/fingerprint required/i, 'Error says so' );

    # Its own audit code, distinct from the malformed one (see t/08 for the
    # /pam/authorize twin).
    my ($ev) =
      grep { ( $_->{reason} // '' ) eq 'fingerprint_required' } @audit;
    is( $ev && $ev->{code},
        'PAM_AUTH_SSH_FP_REQUIRED', 'and its own audit code' );
    count(4);
}

# Leading/trailing whitespace is tolerated (trimmed)
$user_token = _new_pam_token();
$res        = _verify( $user_token, "  $user_fp\n" );
$json       = expectJSON($res);
ok( $json->{valid}, 'fingerprint with whitespace is accepted (trimmed)' );
count(1);

# ------------------------------------------------------------------
# Case 3: unknown fingerprint → rejected (and token consumed)
# ------------------------------------------------------------------

$user_token = _new_pam_token();
$res  = _verify( $user_token, 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' );
$json = expectJSON($res);
ok( !$json->{valid}, 'verify with unknown fingerprint rejected' );
like( $json->{error}, qr/fingerprint/i, 'Error mentions fingerprint' );
count(2);

# Re-submitting the same token after rejection must also fail (consumed)
$res  = _verify( $user_token, $user_fp );
$json = expectJSON($res);
ok( !$json->{valid}, 'token consumed after fingerprint rejection' );
count(1);

# ------------------------------------------------------------------
# Case 4: revoked cert → rejected
# ------------------------------------------------------------------

# Self-revoke via /ssh/myrevoke
my $certsRes = $op->_get(
    '/ssh/mycerts',
    cookie => "lemonldap=$sid",
    accept => 'application/json',
);
my $certsJson = expectJSON($certsRes);
my ($active) =
  grep { ( $_->{fingerprint} || '' ) eq $user_fp }
  @{ $certsJson->{certificates} };
ok( $active && $active->{serial}, 'Active cert found to revoke' );

my $revBody = to_json( { serial => $active->{serial} } );
$res = $op->_post(
    '/ssh/myrevoke',
    IO::String->new($revBody),
    cookie => "lemonldap=$sid",
    type   => 'application/json',
    length => length($revBody),
);
expectOK($res);
count(1);

$user_token = _new_pam_token();
$res  = _verify( $user_token, $user_fp );
$json = expectJSON($res);
ok( !$json->{valid}, 'verify with revoked fingerprint rejected' );
count(1);

# ------------------------------------------------------------------
# Case 5: /pam/authorize + fingerprint binding (same contract)
# ------------------------------------------------------------------

# Sign a fresh key so we have an active cert for the positive case.
my ( $pub2, $fp2 );
{
    my $t = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $t/uk2 -N '' -q -C authz-host") == 0
      or die "ssh-keygen failed";
    open my $fh, '<', "$t/uk2.pub" or die;
    $pub2 = <$fh>;
    close $fh;
    chomp $pub2;
    my $line = `ssh-keygen -l -E sha256 -f $t/uk2.pub`;
    ($fp2) = $line =~ /\b(SHA256:\S+)/;
}

my $signBody2 = to_json(
    {
        public_key    => $pub2,
        validity_days => 1,
        label         => 'my-authz-host',
    }
);
$res = $op->_post(
    '/ssh/sign',
    IO::String->new($signBody2),
    cookie => "lemonldap=$sid",
    type   => 'application/json',
    length => length($signBody2),
);
expectOK($res);

sub _authorize {
    my ($fp) = @_;
    my $body = to_json(
        {
            user         => 'french',
            host         => 'host.example.com',
            service      => 'ssh',
            server_group => 'default',
            ( defined $fp ? ( fingerprint => $fp ) : () ),
        }
    );
    return $op->_post(
        '/pam/authorize',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
}

# No fingerprint → standard behavior preserved
$res  = _authorize(undef);
$json = expectJSON($res);
ok( defined $json->{authorized},
    'authorize without fingerprint returns an answer' );
count(1);

# Matching fingerprint → authorized, cert details surfaced
$res  = _authorize($fp2);
$json = expectJSON($res);
ok( $json->{authorized}, 'authorize with matching fingerprint succeeds' );
is( $json->{ssh_cert_label}, 'my-authz-host',
    'Matched label surfaced in authorize response' );
ok( defined $json->{ssh_cert_serial},
    'Matched serial surfaced in authorize response' );
count(3);

# Unknown fingerprint → denied
$res =
  _authorize('SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
$json = expectJSON($res);
ok( !$json->{authorized}, 'authorize with unknown fingerprint denied' );
like( $json->{reason}, qr/fingerprint/i, 'Reason mentions fingerprint' );
count(2);

# Revoked fingerprint (the $user_fp from case 4) → denied
$res  = _authorize($user_fp);
$json = expectJSON($res);
ok( !$json->{authorized}, 'authorize with revoked fingerprint denied' );
count(1);

# Malformed fingerprint → 400
$res = _authorize('not-a-fingerprint');
is( $res->[0], 400, 'authorize with malformed fingerprint returns 400' );
count(1);

# ------------------------------------------------------------------
# Case 6: the last use of an SSO certificate is recorded (issue #455)
# ------------------------------------------------------------------
{
    no warnings 'once';
    my $USE = $Lemonldap::NG::Portal::Plugins::PamAccess::SSO_CERT_USE_PREFIX;

    # The SSHCA.pm loaded may be LLNG's own, which knows nothing of the use
    # stamps: only the checks that read them through ssh-ca depend on it.
    my $sshcaReadsUse =
      defined $Lemonldap::NG::Portal::Plugins::SSHCA::CERT_USE_PREFIX;
    SKIP: {
        skip 'the SSHCA.pm loaded does not read use stamps', 1
          unless $sshcaReadsUse;
        is( $USE, $Lemonldap::NG::Portal::Plugins::SSHCA::CERT_USE_PREFIX,
            'pam-access and ssh-ca agree on the use key' );
    }
    my $conf = $op->p->conf;
    my $key  = $USE . $fp2;

    my $stamp = sub {
        my $raw = $op->p->getPersistentSession('french')->data->{$key};
        return $raw ? from_json($raw) : undef;
    };
    my $setAt = sub {
        my ($at) = @_;
        my $s = $stamp->();
        $s->{at} = $at;
        $op->p->getPersistentSession('french')->update( { $key => to_json($s) } );
    };

    my $u = $stamp->();
    ok( $u, 'a granted authorize recorded the use' );
    my $rec = from_json( $op->p->getPersistentSession('french')
          ->data->{ $Lemonldap::NG::Portal::Plugins::PamAccess::SSO_CERT_PREFIX
              . $fp2 } );
    is( $u->{serial}, $rec->{serial}, '  -> of this certificate' );
    is( $u->{host}, 'host.example.com', '  -> and the host' );
    cmp_ok( abs( $u->{at} - time ), '<', 30, '  -> just now' );
    count(5);

    # Within pamAccessSshCertUseInterval: no new write.
    my $t = time - 100;
    $setAt->($t);
    expectJSON( _authorize($fp2) );
    is( $stamp->()->{at}, $t,
        'a use within the interval is not written again' );
    count(1);

    # Past it: written again.
    $setAt->( time - 1000 );
    expectJSON( _authorize($fp2) );
    cmp_ok( time - $stamp->()->{at}, '<', 30, 'a later use is written again' );
    count(1);

    # 0 turns recording off.
    {
        local $conf->{pamAccessSshCertUseInterval} = 0;
        $setAt->( time - 1000 );
        expectJSON( _authorize($fp2) );
        cmp_ok( time - $stamp->()->{at},
            '>=', 999, 'pamAccessSshCertUseInterval = 0 records nothing' );
        count(1);
    }

    # A refused authorization is not activity of the certificate: an
    # unknown service is denied by rule, the fingerprint still matching.
    {
        $setAt->( time - 1000 );
        my $body = to_json( {
                user         => 'french',
                host         => 'host.example.com',
                service      => 'ftp',
                server_group => 'default',
                fingerprint  => $fp2,
            }
        );
        my $denied = expectJSON(
            $op->_post(
                '/pam/authorize',
                IO::String->new($body),
                accept => 'application/json',
                type   => 'application/json',
                length => length($body),
                custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
            )
        );
        ok( !$denied->{authorized}, 'authorize refused by rule' );
        cmp_ok( time - $stamp->()->{at},
            '>=', 999, '  -> records no use' );
        count(2);
    }

    # Bastion-hop certificates are not recorded.
    {
        my $pa = $op->p->loadedModules->{
            'Lemonldap::NG::Portal::Plugins::PamAccess'};
        my $ps = $op->p->getPersistentSession('french');
        is_deeply(
            $pa->_sshCertUseUpdate(
                $ps, $fp2, { ok => 1, ephemeral => 1, serial => '9' }, 'h'
            ),
            {},
            'an ephemeral certificate is not recorded'
        );
        ok(
            $pa->_sshCertUseUpdate( $ps, $fp2, { ok => 1, serial => '9' },
                'h' )->{$key},
            '  -> an SSO certificate is'
        );
        count(2);
    }

    # /pam/verify records it too, without a host.
    $setAt->( time - 1000 );
    $json = expectJSON( _verify( _new_pam_token(), $fp2 ) );
    ok( $json->{valid}, 'verify with the certificate' );
    $u = $stamp->();
    cmp_ok( time - $u->{at}, '<', 30, '  -> records the use' );
    ok( !exists $u->{host}, '  -> with no host' );
    count(3);

    # The ssh-ca listing shows it.
    SKIP: {
        skip 'the SSHCA.pm loaded does not read use stamps', 8
          unless $sshcaReadsUse;
        $setAt->( time - 1000 );
        expectJSON( _authorize($fp2) );
        my $list = expectJSON(
            $op->_get(
                '/ssh/mycerts',
                cookie => "lemonldap=$sid",
                accept => 'application/json',
            )
        );
        my ($c) = grep { ( $_->{fingerprint} // '' ) eq $fp2 }
          @{ $list->{certificates} };
        is( $c->{last_used_host}, 'host.example.com',
            '/ssh/mycerts shows where the certificate was last used' );
        cmp_ok( time - $c->{last_used_at}, '<', 30, '  -> and when' );
    }
    count(2);
}

clean_sessions();
done_testing();
