# SSH Certificate Authority plugin for LemonLDAP::NG
#
# This plugin provides SSH certificate signing functionality:
# - /ssh/ca : Public CA key endpoint (no auth required)
# - /ssh/revoked : Key Revocation List (KRL) endpoint (no auth required)
# - /ssh/sign : Sign user's SSH public key (auth required)
# - /ssh/mycerts : List the caller's own certificates (auth required)
# - /ssh/myrevoke : Self-revoke one of the caller's own certificates (auth)
# - /ssh/admin : Administration interface (auth + sshCaAdminRule)
# - /ssh/certs : List/search issued certificates (auth + sshCaAdminRule)
# - /ssh/revoke : Revoke any certificate (auth + sshCaAdminRule)
#
# The three administration endpoints are guarded by `sshCaAdminRule`, a
# boolOrExpr evaluated against the caller's session. It has NO permissive
# default: when it is unset the endpoints answer 403 (see _forbidNonAdmin).
#
# Requires configuration of SSH CA key in LLNG keys store.

package Lemonldap::NG::Portal::Plugins::SSHCA;

use strict;
use Mouse;
use POSIX ();
use JSON qw(from_json to_json);
use Time::HiRes qw(gettimeofday);
use Digest::SHA qw(sha256);
use Encode ();
use MIME::Base64 qw(decode_base64 encode_base64);
use URI;
use Lemonldap::NG::Common::Apache::Session;
use Lemonldap::NG::Handler::Main::MsgActions;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

our $VERSION = '2.23.0';

# Who signs the certificates (sshCaSigner):
#   local   : ssh-keygen -s with the CA private key held in the LLNG
#             configuration (keys/<sshCaKeyRef>/keyPrivate). The historical
#             mode, and the default.
#   openbao : POST <url>/v1/<mount>/sign/<role> on OpenBao's SSH secrets
#             engine, which holds the CA private key (issue #476). LLNG still
#             decides the principals, the validity and the source-address;
#             OpenBao only signs, and the answer is checked against the
#             request before it is handed out.
# The CA public key stays pinned in keys/<sshCaKeyRef>/keyPublic in both
# modes: /ssh/ca, the KRL and sshca-rebuild-krl are built from it.
our %SIGNERS = map { $_ => 1 } qw(local openbao);

# Persistent-session key prefix for issued certificate records, one key per
# certificate ($CERT_PREFIX.<fingerprint>).
#
# Certificates used to share a single `_sshCerts` JSON array, so every sign
# and every revocation was a read-modify-write over a blob the store rewrites
# wholesale: two concurrent /ssh/sign calls, or a revoke racing a sign, lost
# one of the two records (issue #66). Per key, Common::Session->update re-ties
# with noCache => 1 and sets only the named keys, so writers now collide only
# when their tie-to-untie windows overlap — there is still no locking
# (Apache::Session::Lock::Null), but the window is a store round-trip instead
# of a whole request.
#
# The fingerprint is the key because it is what every reader looks up
# (pam-access binds PAM tokens to it) and because re-signing the same key is
# meant to REPLACE its record — which per key is a plain overwrite. Sessions
# written before the upgrade keep their `_sshCerts` array; it is still read,
# and drained into per-key records on the next write.
our $CERT_PREFIX = '_sshCert::';

# A re-signed key used to lose its old record. It is now kept, marked
# `superseded_at`, under its serial: the fingerprint key belongs to the record
# that replaced it (issue #455). sshCaCertHistoryMax and
# sshCaCertHistoryRetention bound how many are kept and for how long.
our $CERT_OLD_PREFIX = '_sshCertOld::';

# Last use of the certificate behind a fingerprint, written by pam-access
# ($SSO_CERT_USE_PREFIX there) when /pam/authorize or /pam/verify matches it:
# { serial, at, host }. A key of its own, so pam-access never rewrites a
# certificate record (a stamp racing a revocation would otherwise be able to
# lose `revoked_at`). The serial tells which certificate of that key it
# belongs to.
our $CERT_USE_PREFIX = '_sshCertUse::';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'SSHCA';

# Key policy defaults (see sshCaAllowedKeyTypes / sshCaMinKeyBits).
#
# `ssh-dss` is deliberately absent: DSA is capped at 1024-bit keys with
# SHA-1 signatures, has been disabled at compile time in OpenSSH since 9.8
# and removed outright in OpenSSH 10. Operators who still need it can put
# `dss` back in sshCaAllowedKeyTypes.
use constant SSHCA_DEFAULT_KEY_TYPES => 'ed25519,ecdsa,sk-ed25519,sk-ecdsa,rsa';
use constant SSHCA_DEFAULT_MIN_BITS  => 2048;

# Key types whose size is fixed by the algorithm/curve. `family` is the
# token used in sshCaAllowedKeyTypes, `bits` the effective key size — these
# are NOT comparable with an RSA modulus size, hence `sized => 0`: the
# sshCaMinKeyBits floor only applies to variable-size families.
my %SSHCA_FIXED_KEY_TYPES = (
    'ssh-ed25519'                        => [ 'ed25519',  256 ],
    'sk-ssh-ed25519@openssh.com'         => [ 'sk-ed25519', 256 ],
    'ecdsa-sha2-nistp256'                => [ 'ecdsa',    256 ],
    'ecdsa-sha2-nistp384'                => [ 'ecdsa',    384 ],
    'ecdsa-sha2-nistp521'                => [ 'ecdsa',    521 ],
    'sk-ecdsa-sha2-nistp256@openssh.com' => [ 'sk-ecdsa', 256 ],
);

# ECDSA types: the curve name the blob must carry, then the size of its
# uncompressed point (0x04 || X || Y). OpenSSH (sshkey_ecdsa_nid_from_name)
# refuses a key whose curve field disagrees with its type, so sizing one from
# its type name would grade material the key does not hold.
my %SSHCA_ECDSA_CURVES = (
    'ecdsa-sha2-nistp256'                => [ 'nistp256', 1 + 2 * 32 ],
    'ecdsa-sha2-nistp384'                => [ 'nistp384', 1 + 2 * 48 ],
    'ecdsa-sha2-nistp521'                => [ 'nistp521', 1 + 2 * 66 ],
    'sk-ecdsa-sha2-nistp256@openssh.com' => [ 'nistp256', 1 + 2 * 32 ],
);

has key => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        $_[0]->conf->{sshCaKeyRef}
          ? $_[0]->conf->{keys}->{ $_[0]->conf->{sshCaKeyRef} }
          : undef;
    },
);

has sshPubKey  => ( is => 'rw' );
has sshPrivKey => ( is => 'rw' );

# `local` or `openbao`, set by init(). Anything that runs before init (or
# without it) signs locally, as the plugin always did.
has signer => ( is => 'rw', default => 'local' );

# Validated OpenBao settings (openbao mode only), see _openBaoConf. Undefined
# when the signer is `local`, or when the OpenBao configuration is incomplete,
# in which case init() refuses to load the plugin anyway.
has baoConf => ( is => 'rw' );

# AppRole token, cached per worker with its expiry (epoch). Never logged.
has _baoToken    => ( is => 'rw' );
has _baoTokenExp => ( is => 'rw', default => 0 );

# HTTP client for OpenBao. Built on first use so that the `local` signer
# never loads LWP.
has ua => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        my ($self) = @_;
        require Lemonldap::NG::Common::UserAgent;
        my $bao = $self->baoConf || {};

        # Copies: Common::UserAgent writes its defaults into the lwpOpts hash
        # it is given, which must not leak into the shared configuration.
        my %lwp = %{ $self->conf->{lwpOpts} || {} };
        $lwp{timeout} = $bao->{timeout} || 5;
        my %ssl = %{ $self->conf->{lwpSslOpts} || {} };
        $ssl{SSL_ca_file} = $bao->{caFile} if $bao->{caFile};
        my $ua = Lemonldap::NG::Common::UserAgent->new( {
                lwpOpts => \%lwp,
                ( %ssl ? ( lwpSslOpts => \%ssl ) : () ),
            }
        );

        # No redirects. Common::UserAgent makes POST redirectable, and LWP
        # resends the X-Vault-Token header (and, on 307/308, the body with the
        # AppRole secret_id) to whatever host the Location names. A 3xx is
        # then just a failed request.
        $ua->max_redirect(0);
        $ua->requests_redirectable( [] );

        # OpenBao answers are small: a hostile or broken endpoint must not
        # make a portal worker buffer an unbounded body.
        $ua->max_size( 1024 * 1024 );
        return $ua;
    },
);

# Compiled `sshCaAdminRule`. Always a code ref after init(): when the
# parameter is unset or does not compile, it is the constant-false sub, so
# every code path that consults it fails closed.
has adminRule => ( is => 'rw' );

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Select the signer (issue #476)
    my $signer = $self->conf->{sshCaSigner};
    $signer = '' unless defined $signer && !ref $signer;
    $signer =~ s/^\s+|\s+$//g;
    $signer = lc( $signer || 'local' );
    unless ( $SIGNERS{$signer} ) {
        $self->logger->error(
            "SSH CA: unknown sshCaSigner '$signer' (expected local or openbao)"
        );
        return 0;
    }
    $self->signer($signer);

    # Check parameters. OpenBao holds the private key in `openbao` mode, so
    # only the public half is needed there.
    unless ( $self->key
        and ref $self->key
        and $self->key->{keyPublic}
        and ( $signer eq 'openbao' or $self->key->{keyPrivate} ) )
    {
        $self->logger->error('SSH CA Key not configured');
        return 0;
    }

    unless (
        $self->sshPubKey(
            $self->_pemToSshPublicKey(
                $self->key->{keyPublic},
                $self->conf->{sshCaKeyRef}
            )
        )
      )
    {
        $self->logger->error(
            'SSH CA: Failed to convert public key to SSH format');
        return 0;
    }

    if ( $signer eq 'openbao' ) {

        # Fail closed: an incomplete OpenBao configuration must not leave a
        # plugin that answers every signature with an error, and must never
        # fall back to a local key.
        my $bao = $self->_openBaoConf or return 0;
        $self->baoConf($bao);

        # The point of this mode is that the private key leaves the LLNG
        # configuration: say so if it is still there. It is never used.
        $self->logger->warn( 'SSH CA: sshCaSigner is openbao, the private key '
              . 'of keys/'
              . $self->conf->{sshCaKeyRef}
              . ' is ignored and should be removed from the configuration' )
          if $self->key->{keyPrivate};

        # A role pointing at the wrong issuer would only show at the first
        # signature (every certificate refused). Ask OpenBao for its CA key
        # now; a network failure is not fatal, OpenBao may simply be down
        # while the portal starts.
        $self->_checkOpenBaoPublicKey;
    }
    else {
        unless (
            $self->sshPrivKey(
                $self->_pemToOpenSSHPrivateKey( $self->key->{keyPrivate} )
            )
          )
        {
            $self->logger->error(
                'SSH CA: Failed to convert private key to SSH format');
            return 0;
        }
        $self->sshPrivKey( $self->sshPrivKey . "\n" )
          unless $self->sshPrivKey =~ /\n$/s;
    }

    # Build the administration rule (issue #58).
    #
    # /ssh/admin, /ssh/certs and /ssh/revoke expose EVERY user's certificates
    # and let the caller revoke any of them. They used to rely solely on
    # locationRules being set on the portal vhost, which is not a default
    # deny: a portal whose vhost has `"default": "accept"` and no `^/ssh`
    # rule (the shape shipped by every open-bastion config) handed full SSH
    # CA administration to any authenticated user. The plugin now carries its
    # own rule and denies when it is unset — an unconfigured deployment loses
    # the admin UI, never the other way round.
    my $adminRule = $self->conf->{sshCaAdminRule};
    $adminRule = '' unless defined $adminRule;
    $adminRule =~ s/^\s+|\s+$//g;
    if ( $adminRule eq '' or $adminRule eq '0' ) {
        $self->logger->warn(
                'SSH CA: sshCaAdminRule is not set, the administration '
              . 'endpoints (/ssh/admin, /ssh/certs, /ssh/revoke) are denied' );
        $self->adminRule( sub { 0 } );
    }
    else {
        my $rule = $self->p->buildRule( $adminRule, 'sshCaAdmin' );
        unless ($rule) {

            # buildRule() already logged the compilation error. Fail closed on
            # the admin endpoints only: users must still be able to sign their
            # own keys, so don't abort the whole plugin.
            $self->logger->error(
                    'SSH CA: unable to compile sshCaAdminRule, the '
                  . 'administration endpoints are denied' );
            $rule = sub { 0 };
        }
        $self->adminRule($rule);
    }

    # GET /ssh/ca - Public CA key (no auth required)
    $self->addUnauthRoute(
        ssh => { ca => 'sshCaPublicKey' },
        ['GET']
    )

      # POST /ssh/sign - Sign user's SSH key (auth required)
      ->addAuthRoute(
        ssh => { sign => 'sshCaSign' },
        ['POST']
      )

      # GET /ssh/mycerts - List current user's certificates (auth required)
      ->addAuthRoute(
        ssh => { mycerts => 'sshMyCerts' },
        ['GET']
      )

      # POST /ssh/myrevoke - User revokes one of their own certificates
      ->addAuthRoute(
        ssh => { myrevoke => 'sshMyCertRevoke' },
        ['POST']
      )

      # GET /ssh/admin - Display the revocation interface (auth required, admin)
      ->addAuthRoute(
        ssh => { admin => 'sshAdminInterface' },
        ['GET']
      )

      # GET /ssh/certs - List/search certificates (auth required, admin)
      ->addAuthRoute(
        ssh => { certs => 'sshCertsList' },
        ['GET']
      )

      # POST /ssh/revoke - Revoke a certificate (auth required, admin)
      ->addAuthRoute(
        ssh => { revoke => 'sshCertRevoke' },
        ['POST']
      )

      # GET /ssh - Display the signing interface (standalone page, auth required)
      ->addAuthRoute(
        ssh => { '*' => 'sshInterface' },
        ['GET']
      )

      # Redirect unauthenticated users to portal for /ssh (except /ssh/ca and /ssh/revoked)
      ->addUnauthRoute(
        ssh => { '*' => 'sshRedirectToPortal' },
        ['GET']
      );

    # GET /ssh/revoked - Key Revocation List (no auth required)
    unless ( $self->conf->{sshCaKrlPath} ) {
        $self->logger->error('SSH CA: No KRL path configured');
    }
    else {
        $self->addUnauthRoute(
            ssh => { revoked => 'sshCaKrl' },
            ['GET']
        )->addAuthRoute(
            ssh => { revoked => 'sshCaKrl' },
            ['GET']
        );

        # Make sure a *parsable* KRL exists from the start (issue #64).
        # Serving an empty body (or nothing at all) leaves consumers with a
        # file sshd cannot parse as a KRL; a header-only KRL generated by
        # ssh-keygen is the correct representation of "nothing revoked yet".
        $self->_ensureKrl( $self->conf->{sshCaKrlPath} );
    }

    # Multi-node replication of the KRL (issue #9). The KRL file is local to
    # each portal host, so a revocation on node A must be propagated to node B.
    # We rely on LLNG's message broker (requires ::Redis / ::MQTT / ::Pg — the
    # default ::NoBroker only dispatches in-process). Every node registers a
    # handler that updates its own KRL file on receiving a 'sshCaRevoke' event.
    # Drift recovery (broker outage, node added later) is handled out of band
    # by the external sshca-rebuild-krl cron script, which scans the
    # persistent sessions (source of truth) and rewrites the local KRL.
    Lemonldap::NG::Handler::Main::MsgActions::addMsgAction(
        'sshCaRevoke',
        sub {
            my ( $class, $msg, $req ) = @_;
            my $serial = $msg->{serial};

            # The broker payload is the only path into _updateKrl that is not
            # matched against a stored certificate record first, so validate
            # it here (issue #65): the serial ends up verbatim in the
            # ssh-keygen KRL spec file, where a newline would inject extra
            # directives (`id:`, `key:`, `hash:`).
            unless ( $self->_validSerial($serial) ) {
                $self->logger->error(
                    'SSH CA: ignoring sshCaRevoke event with invalid serial');
                return;
            }
            $self->logger->debug(
                "SSH CA: broker event sshCaRevoke serial=$serial");
            $self->_updateKrl($serial);
        }
    );

    $self->logger->debug('SSH CA plugin initialized');

    return 1;
}

# Redirect unauthenticated users to portal (preserving REQUEST_URI)
sub sshRedirectToPortal {
    my ( $self, $req ) = @_;
    $self->p->api->goToPortal( $req, $req->{env}->{REQUEST_URI} );
    return $self->p->sendRedirection($req);
}

# GET /ssh - Display the signing interface (standalone page)
sub sshInterface {
    my ( $self, $req ) = @_;

    my $maxValidityDays = $self->conf->{sshCaCertMaxValidity} || 365;

    return $self->p->sendHtml(
        $req, 'sshca',
        params => {
            MAX_VALIDITY_DAYS => $maxValidityDays,
            js => "$self->{p}->{staticPrefix}/common/js/sshca.js",
        }
    );
}

# =============================================================================
# ROUTE HANDLERS
# =============================================================================

# GET /ssh/ca.pub - Return SSH CA public key
sub sshCaPublicKey {
    my ( $self, $req ) = @_;

    return [
        200,
        [
            'Content-Type'  => 'text/plain; charset=utf-8',
            'Cache-Control' => 'public, max-age=3600',
        ],
        [ $self->sshPubKey ]
    ];
}

# GET /ssh/revoked - Return SSH Key Revocation List (KRL)
sub sshCaKrl {
    my ( $self, $req ) = @_;

    my $krlPath = $self->conf->{sshCaKrlPath};

    # No KRL yet (fresh install, or the file was removed): generate a valid
    # empty one rather than serving an empty body (issue #64). This is a
    # no-op once the file exists, so the normal path costs one stat().
    $self->_ensureKrl($krlPath) unless $krlPath and -s $krlPath;

    unless ( $krlPath and -f $krlPath ) {

        # Generation failed (no ssh-keygen, unwritable directory, ...).
        # Keep the historical empty-body answer: sshd falls back to its
        # flat-key-file parser on an unparsable RevokedKeys, so this is a
        # fail-open (revocations unenforced) but not a lockout.
        $self->logger->error(
            'SSH CA: no KRL available, returning an empty response');
        return [
            200,
            [
                'Content-Type'  => 'application/octet-stream',
                'Cache-Control' => 'public, max-age=300',
            ],
            ['']
        ];
    }

    # Shared lock: pairs with the exclusive lock taken by _writeKrl. The
    # rename() there already makes torn reads impossible; this just keeps a
    # reader from racing an in-progress rebuild on filesystems where that
    # guarantee is weaker. Best effort — a lock failure never fails the read.
    my $krlData;
    {
        my $lockFh = $self->_krlLock( $krlPath, 1 );
        open my $fh, '<:raw', $krlPath or do {
            $self->logger->error("SSH CA: Cannot read KRL file: $!");
            return $self->p->sendError( $req, 'Cannot read KRL', 500 );
        };
        local $/;
        $krlData = <$fh>;
        close $fh;

        # $lockFh is released here, on every exit path (including the die-less
        # early return above, which unwinds the same lexical scope).
    }

    # Never hand out a KRL we cannot parse (issue #59). A KRL truncated
    # mid-write keeps a valid `SSHKRL` magic, and sshd then fails *closed* on
    # every key it checks ("incomplete message"), locking the host out
    # entirely. Consumers only check the magic, so the check has to happen
    # here.
    unless ( $self->_krlIsValid($krlData) ) {
        $self->logger->error(
            "SSH CA: refusing to serve a corrupted KRL ($krlPath)");
        return $self->p->sendError( $req, 'Corrupted KRL', 500 );
    }

    $self->logger->debug('SSH CA: Serving KRL');

    return [
        200,
        [
            'Content-Type'  => 'application/octet-stream',
            'Cache-Control' => 'public, max-age=300',
        ],
        [$krlData]
    ];
}

# POST /ssh/sign - Sign user's SSH public key
# HELPER: decode the JSON body of a POST route, refusing what a cross-site
# form could produce (issue #62).
#
# The three POST routes used to call from_json on $req->content directly,
# bypassing the core's jsonBodyToObj and therefore its `Content-Type:
# application/json` requirement. That matters because an HTML form can only
# send application/x-www-form-urlencoded, multipart/form-data or text/plain —
# and a text/plain body containing JSON parsed cleanly. So a page on another
# origin could POST to /ssh/sign, /ssh/myrevoke and /ssh/revoke with the
# victim's cookie, whenever the SSO cookie is SameSite=None (which LLNG sets
# for SAML deployments).
#
# Nothing is disclosed that way: the certificate is only in a response body
# the attacker's page cannot read. The damage is a forced state change —
# re-signing a victim's (public) public key supersedes their live certificate
# and KRL-revokes the old serial, locking them out of SSH; a forced
# /ssh/myrevoke does the same in one step.
#
# The Origin check is the other half. Browsers attach Origin to every
# cross-origin POST, so a present-but-foreign Origin is refused outright.
# Non-browser callers — the ssh-ca CLI, curl, ob-* tooling — send none and are
# unaffected.
#
# Returns ($body, undef) or (undef, $response).
sub _jsonBodyOrReject {
    my ( $self, $req, $label ) = @_;

    if ( my $origin = $req->origin ) {
        unless ( $self->_isSelfOrigin( $req, $origin ) ) {
            $self->logger->warn(
                "$label: refused a cross-origin request from '$origin'");
            $self->p->auditLog(
                $req,
                code    => 'SSH_CA_CROSS_ORIGIN_REFUSED',
                message => "SSH CA: cross-origin $label refused",
                origin  => $origin,
            );
            return ( undef,
                $self->p->sendError( $req, 'Cross-origin request refused',
                    403 ) );
        }
    }

    my $body = $req->jsonBodyToObj;
    unless ( ref $body eq 'HASH' ) {
        my $err = $req->error || 'Invalid JSON';
        $self->logger->error("$label: $err");

        # $req->error is sticky (the setter ignores undef), and a leftover
        # "Data is not JSON" would surface in an unrelated later message.
        delete $req->{error};
        return ( undef, $self->p->sendError( $req, 'Invalid JSON', 400 ) );
    }

    return ( $body, undef );
}

# HELPER: does $origin designate this very portal?
# Same rule as the core's _checkSelfCors: scheme and host:port must match.
sub _isSelfOrigin {
    my ( $self, $req, $origin ) = @_;

    my $o = URI->new($origin);
    my $p = URI->new( $req->portal || $self->conf->{portal} || '' );
    return (  $o->scheme
          and $p->scheme
          and $o->scheme eq $p->scheme
          and $o->can('host_port')
          and $o->host_port
          and $p->can('host_port')
          and $o->host_port eq $p->host_port ) ? 1 : 0;
}

# HELPER: a configuration value that must be a non-negative integer.
# Anything else (unset, empty, "twenty", -1) falls back to $default, so a
# typo in the Manager cannot silently disable a limit.
sub _positiveIntConf {
    my ( $self, $key, $default ) = @_;

    my $v = $self->conf->{$key};
    return $default unless defined $v and $v =~ /\A[0-9]+\z/;
    return $v + 0;
}

# HELPER: per-user rate limit on /ssh/sign (issue #63).
#
# Why it matters here specifically: every signature forks ssh-keygen twice and
# rewrites the WHOLE KRL as a read-modify-write, and re-signing the same key
# appends the superseded serial — which /ssh/sign explicitly allows, so a loop
# grows the KRL without bound. The cost per call therefore grows with the KRL,
# and every appended serial is then loaded by every sshd on every backend. An
# authenticated user could turn that into a fleet-wide denial of service for
# the price of a shell loop.
#
# A fixed window (sshCaSignMaxPerHour, 20/hour, 0 = unlimited) counted in the
# user's own persistent session: the session store is already shared across
# nodes, so the count is cluster-wide with no new dependency. Two signatures
# racing can under-count by one — the store has no atomic increment — which is
# irrelevant for a limit whose purpose is to bound a loop, not to be exact.
#
# Returns a response when the caller is over the limit, undef otherwise.
sub _rateLimitSign {
    my ( $self, $req ) = @_;

    my $max = $self->_positiveIntConf( 'sshCaSignMaxPerHour', 20 );
    return undef unless $max;

    my $user = $req->user;
    unless ( defined $user and $user ne '' ) {

        # No identity to count against: /ssh/sign is an authenticated route,
        # so this should not happen. Refuse rather than hand out a free pass.
        $self->logger->error(
            'SSH CA sign: no user in session, refusing to sign unmetered');
        return $self->p->sendError( $req, 'Unauthorized', 403 );
    }

    my $now    = time();
    my $window = 3600;
    my $raw    = $req->userData->{_sshCaSignRate};
    my $state  = $raw ? eval { from_json($raw) } : undef;
    $state = undef unless ref $state eq 'HASH';

    my $start = $state->{start} || 0;
    my $count = $state->{count} || 0;
    if ( $now - $start >= $window ) {
        ( $start, $count ) = ( $now, 0 );
    }

    if ( $count >= $max ) {
        my $retry = $start + $window - $now;
        $retry = 1 if $retry < 1;
        $self->logger->warn( "SSH CA sign: rate limit reached for '$user' "
              . "($count/$max in the current hour)" );
        $self->p->auditLog(
            $req,
            code    => 'SSH_CA_SIGN_RATE_LIMITED',
            user    => $user,
            message => "SSH CA: /ssh/sign rate limit reached for '$user'",
            count   => $count,
            limit   => $max,
        );
        push @{ $req->respHeaders }, 'Retry-After' => $retry;
        return $self->p->sendJSONresponse(
            $req,
            {
                error       => 'Rate limit exceeded',
                limit       => $max,
                retry_after => $retry,
            },
            code => 429
        );
    }

    $self->p->updatePersistentSession( $req,
        { _sshCaSignRate => to_json( { start => $start, count => $count + 1 } ) }
    );

    return undef;
}

sub sshCaSign {
    my ( $self, $req ) = @_;

    my ( $body, $bail ) = $self->_jsonBodyOrReject( $req, 'SSH CA sign' );
    return $bail if $bail;

    # Rate limit before anything expensive: key validation, the policy check,
    # the ssh-keygen fork and the KRL rewrite all sit below this line, and the
    # point of the limit is that an abusive caller must not be able to make
    # the portal do that work (issue #63).
    #
    # The JSON body has already been decoded just above -- a refused caller
    # still pays that, deliberately: a malformed body must answer 400 whether
    # or not the caller is over its quota, otherwise the limit would turn a
    # client bug into a misleading 429.
    if ( my $limited = $self->_rateLimitSign($req) ) {
        return $limited;
    }

    my $userPubKey = $body->{public_key};
    unless ($userPubKey) {
        return $self->p->sendError( $req, 'public_key parameter required',
            400 );
    }

   # Validate SSH public key format: type, base64, optional comment, single line
   # Strict validation to prevent injection attacks. The `sk-*@openssh.com`
   # families are FIDO2/hardware-backed keys — they must be accepted here,
   # their `@` and `.` are not matched by \w.
    unless (
        $userPubKey =~ m{
            \A
            (?:
                 ssh-[\w-]+                       # ssh-ed25519, ssh-rsa, ...
               | ecdsa-sha2-\w+                   # ecdsa-sha2-nistp256, ...
               | sk-ssh-[\w-]+\@openssh\.com      # FIDO2 Ed25519
               | sk-ecdsa-sha2-\w+\@openssh\.com  # FIDO2 ECDSA
            )
            \s+ [A-Za-z0-9+/]+={0,2}
            (?: \s+ [^\r\n]* )?
            \z
        }x
      )
    {
        return $self->p->sendError( $req, 'Invalid SSH public key format',
            400 );
    }

    # Enforce the key type / key size policy. The verdict comes from the
    # DECODED wire-format blob, never from the textual prefix.
    my $policy = $self->_checkKeyPolicy($userPubKey);
    unless ( $policy->{ok} ) {
        $self->logger->warn( "SSH CA sign: rejected key for user "
              . ( $req->user || 'unknown' ) . ": "
              . $policy->{error} );
        return $self->p->sendError( $req, $policy->{error}, 400 );
    }

    # Label is mandatory (client-side also required). Fallback: extract from the
    # SSH public key's comment (third token) for backward-compat with records
    # signed before label support.
    my $label = $body->{label};
    $label = '' unless defined $label;
    $label =~ s/^\s+|\s+$//g;
    if ( $label eq '' && $userPubKey =~ /^\S+\s+\S+\s+(.+\S)\s*$/ ) {
        $label = $1;
    }
    if ( $label eq '' ) {
        return $self->p->sendError( $req, 'label parameter required', 400 );
    }
    if ( length($label) > 128 || $label =~ /[\r\n\t]/ ) {
        return $self->p->sendError( $req, 'Invalid label', 400 );
    }

    # Compute SSH key fingerprint (SHA256:...) — used for dedup and PAM lookup
    my $fingerprint = $self->_sshKeyFingerprint($userPubKey);
    unless ($fingerprint) {
        $self->logger->error('SSH CA sign: Cannot compute fingerprint');
        return $self->p->sendError( $req, 'Cannot compute key fingerprint',
            400 );
    }

    # Enforce label uniqueness within the user's (non-revoked, non-expired)
    # certificates — except when the same label is reused for the SAME key
    # (re-signing): in that case the old record is going to be replaced.
    my $existingCerts = $self->_certsFromData( $req->userData );
    my $now    = time();
    my $active = 0;
    my $resign = 0;
    for my $c (@$existingCerts) {
        next if $c->{revoked_at};
        next if $c->{superseded_at};
        next if $c->{expires_at} && $c->{expires_at} < $now;
        $active++;
        $resign = 1 if ( $c->{fingerprint} || '' ) eq $fingerprint;
        next unless ( $c->{label} || '' ) eq $label;
        next if ( $c->{fingerprint} || '' ) eq $fingerprint;
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Label already used for another key' },
            code => 409
        );
    }

    # Cap the number of live certificates a user may hold (issue #63). A
    # re-signature replaces an existing record, so it never grows the set and
    # is not counted. Users clear room with /ssh/myrevoke.
    my $maxCerts = $self->_positiveIntConf( 'sshCaMaxCertsPerUser', 20 );
    if ( $maxCerts and !$resign and $active >= $maxCerts ) {
        my $user = $req->user || 'unknown';
        $self->logger->warn(
            "SSH CA sign: '$user' already holds $active active certificates"
              . " (sshCaMaxCertsPerUser=$maxCerts)" );
        $self->p->auditLog(
            $req,
            code    => 'SSH_CA_CERT_QUOTA_EXCEEDED',
            user    => $user,
            message => "SSH CA: certificate quota reached for '$user'",
            active  => $active,
            limit   => $maxCerts,
        );
        return $self->p->sendJSONresponse(
            $req,
            {
                error => 'Certificate quota reached',
                limit => $maxCerts,
            },
            code => 409
        );
    }

    # Get validity from request (in days) or default to 30 days. It reaches
    # ssh-keygen as `-V +<n>m`, so a non-numeric value ("abc" -> 0) would
    # mint a sub-minute certificate and a negative one would make ssh-keygen
    # fail with a 500: only a positive integer is acceptable.
    my $validityDays = $body->{validity_days};
    $validityDays = 30 unless defined $validityDays && $validityDays ne '';
    unless ( !ref($validityDays)
        && $validityDays =~ /\A[0-9]+\z/
        && $validityDays > 0 )
    {
        return $self->p->sendError( $req,
            'validity_days must be a positive integer', 400 );
    }

    # Enforce maximum validity (in days, default 365)
    my $maxValidityDays = $self->conf->{sshCaCertMaxValidity} || 365;
    $validityDays = $maxValidityDays if $validityDays > $maxValidityDays;

    # Convert to minutes for ssh-keygen
    my $validityMinutes = $validityDays * 24 * 60;

 # SECURITY: Always derive principals from the authenticated user's session
 # Never trust principals from the request body to prevent impersonation attacks
    my @principals;

    # Evaluate principal sources from config (e.g., '$uid' or '$uid $mail')
    my $principalSources = $self->conf->{sshCaPrincipalSources} || '$uid';

    # Safe variable substitution without using /e to avoid eval-like behavior
    my $principal = '';
    my $template  = $principalSources;
    my $pos       = 0;

    while ( $template =~ /\$(\w+)/g ) {
        my $match_start = $-[0];
        my $match_end   = $+[0];

        # Append text before the match
        $principal .= substr( $template, $pos, $match_start - $pos );

        # Get value from userData or sessionInfo
        my $key = $1;
        my $val = $req->userData->{$key};
        $val = $req->sessionInfo->{$key} if !defined $val || $val eq '';
        $val = ''                        if !defined $val;

        # Strip characters that could turn a single attribute value into
        # multiple principals downstream: `,` is ssh-keygen -n's separator
        # (`-n alice,root` = two principals), and both `,` and whitespace are
        # the template's own separators (we split on /[\s,]+/ below). CR/LF
        # would additionally poison audit logs and any file handed to
        # ssh-keygen. Each `$var` substitution must yield at most one
        # principal token, so match the same `\s` class the split uses --
        # `tr///` cannot do that, hence the regex.
        if ( $val =~ s/[\s,]//g ) {
            $self->logger->warn(
                "SSH CA sign: stripped separator chars from principal "
                  . "source \$$key for user "
                  . ( $req->user || 'unknown' ) );
        }

        $principal .= $val;
        $pos = $match_end;
    }

    # Append remaining text after last match
    $principal .= substr( $template, $pos ) if $pos < length($template);
    $principal =~ s/^\s+|\s+$//g;    # trim

    # Split on whitespace or commas if multiple principals
    @principals = grep { $_ ne '' } split /[\s,]+/, $principal;

  # Log warning if client tried to specify principals (potential attack attempt)
    if ( $body->{principals} && ref $body->{principals} eq 'ARRAY' ) {
        $self->logger->warn(
                "SSH CA sign: Ignoring 'principals' parameter from request "
              . "(user: "
              . ( $req->user || 'unknown' ) . "). "
              . "Principals are always derived from session for security." );
    }

    unless (@principals) {
        $self->logger->error('SSH CA sign: No principals available');
        return $self->p->sendError( $req, 'No principals available', 400 );
    }

    # ssh-keygen receives -n and -I as C strings through exec: a NUL would
    # truncate the argument, so the certificate could carry a principal (or a
    # key id) that is not the one computed from the session. Control
    # characters would also poison the logs and the audit trail. Refuse the
    # request rather than sign something else.
    for my $principal (@principals) {
        next unless $principal =~ /[\x00-\x1f\x7f]/;
        $self->logger->warn(
            'SSH CA sign: refusing a principal with unsafe characters for user '
              . ( $req->user || 'unknown' ) );
        return $self->p->sendError( $req, 'Invalid principal', 400 );
    }

    # Get user info for key_id
    my $whatToTrace = $self->conf->{whatToTrace} || 'uid';
    my $user =
         $req->userData->{$whatToTrace}
      || $req->sessionInfo->{$whatToTrace}
      || $req->userData->{uid}
      || $req->sessionInfo->{uid}
      || $req->user
      || 'unknown';

    if ( $user =~ /[\x00-\x1f\x7f]/ ) {
        $self->logger->warn(
            'SSH CA sign: refusing a user with control characters');
        return $self->p->sendError(
            $req, 'Invalid user for SSH certificate', 400 );
    }

    # Generate serial number and key_id. OpenBao chooses the serial itself
    # (random 64-bit, it cannot be imposed), so it is only known once the
    # certificate is back: the key_id carries a random nonce instead.
    my $timestamp = time();
    my ( $serial, $keyId );
    if ( $self->signer eq 'openbao' ) {
        $keyId = sprintf( "%s\@llng-%d-%s", $user, $timestamp, _nonceHex(8) );
    }
    else {
        $serial = $self->_getNextSerial();
        $keyId  = sprintf( "%s\@llng-%d-%06d", $user, $timestamp, $serial );
    }

    # Sign the certificate
    my $result =
      $self->_signSshKey( $userPubKey, \@principals, $validityMinutes, $serial,
        $keyId );

    unless ( $result && $result->{certificate} ) {
        $self->logger->error('SSH CA sign: Failed to sign key');

        # OpenBao unreachable, sealed or refusing: a dependency is down, not
        # a bug of this portal (issue #476).
        my $unavailable =
          $result && ( $result->{error} || '' ) eq 'unavailable';
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Failed to sign SSH key' },
            code => $unavailable ? 503 : 500
        );
    }

    # The serial the certificate really carries: the one generated above in
    # local mode, the one OpenBao chose otherwise. It is recorded and goes
    # into the KRL, so never record anything else.
    $serial = $result->{serial};
    unless ( $self->_validSerial($serial) ) {
        $self->logger->error('SSH CA sign: signer returned no usable serial');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Failed to sign SSH key' },
            code => 500
        );
    }

    # Calculate expiration time
    my $validUntil    = time() + ( $validityMinutes * 60 );
    my @t             = gmtime($validUntil);
    my $validUntilISO = sprintf(
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $t[5] + 1900,
        $t[4] + 1,
        $t[3], $t[2], $t[1], $t[0]
    );

    $self->logger->info( "SSH CA: Certificate issued for user '$user', "
          . "principals: "
          . join( ',', @principals ) . ", "
          . "validity: ${validityMinutes}min, serial: $serial" );

    # Store certificate in persistent session for revocation tracking.
    # _storeCertificate replaces any existing record with the same fingerprint
    # and revokes the superseded serial in the KRL. Pass the already-decoded
    # $existingCerts so the helper doesn't re-run from_json on the same blob.
    $self->_storeCertificate(
        $req,
        existing    => $existingCerts,
        serial      => $serial,
        key_id      => $keyId,
        user        => $user,
        label       => $label,
        fingerprint => $fingerprint,
        principals  => \@principals,
        issued_at   => $timestamp,
        expires_at  => $validUntil,
    );

    # Audit log
    $self->p->auditLog(
        $req,
        code        => 'SSH_CERT_ISSUED',
        user        => $user,
        message     => "SSH certificate issued for user '$user'",
        principals  => \@principals,
        serial      => $serial,
        key_id      => $keyId,
        label       => $label,
        fingerprint => $fingerprint,
        validity    => $validityMinutes,
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            certificate => $result->{certificate},
            serial      => $serial,
            valid_until => $validUntilISO,
            principals  => \@principals,
            key_id      => $keyId,
            label       => $label,
            fingerprint => $fingerprint,
        }
    );
}

# =============================================================================
# HELPER METHODS
# =============================================================================

# HELPER: Generate a unique certificate serial.
#
# Multi-portal deployments (issue #9) rule out a shared counter file: each
# node would increment its own and produce duplicates. Instead we derive the
# serial from the wall clock in microseconds plus a small random tail:
#   serial = seconds * 1_000_000_000 + microseconds * 1_000 + rand(0..999)
# That fits in an unsigned 63-bit integer (ssh-keygen accepts up to 2^64-1).
#
# Two safeguards on top of rand():
#   - per-process monotonic: we remember the last (s, us) and bump µs forward
#     if the clock tick hasn't advanced (or stepped backwards), which rules
#     out intra-process collisions even on coarse/NTP-adjusted clocks.
#   - cross-node collision probability within the same µs stays at 1/1000,
#     which is acceptable for SSH CA issuance rates. The KRL keys on serial,
#     so any clash would be caught there and can be retried.
{
    my ( $last_s, $last_us ) = ( 0, 0 );

    sub _getNextSerial {
        my ($self) = @_;
        my ( $s, $us ) = gettimeofday();
        if ( $s < $last_s || ( $s == $last_s && $us <= $last_us ) ) {
            ( $s, $us ) = ( $last_s, $last_us + 1 );
            if ( $us >= 1_000_000 ) { $s++; $us = 0; }
        }
        ( $last_s, $last_us ) = ( $s, $us );
        return $s * 1_000_000_000 + $us * 1_000 + int( rand(1000) );
    }
}

# Is the configured signer usable? pam-access asks before minting a bastion
# hop certificate. `local` needs the converted CA private key, `openbao` a
# complete OpenBao configuration (whether OpenBao answers is only known when
# signing).
sub canSign {
    my ($self) = @_;
    if ( $self->signer eq 'openbao' ) {
        return $self->baoConf ? 1 : 0;
    }
    return $self->sshPrivKey ? 1 : 0;
}

# HELPER: Sign an SSH key with the configured signer.
#
# $serial is the serial to impose; OpenBao chooses its own and ignores it.
# $opts (optional hashref) lets callers other than the interactive /ssh/sign
# route (e.g. pam-access bastion-cert vouching) tighten the certificate:
#   - validity       : explicit ssh-keygen -V spec (e.g. "+120s"), overrides
#                      the $validityMinutes argument. Enables sub-minute TTLs.
#                      Only `+<n>s` and `+<n>m` are understood by `openbao`.
#   - source_address : value for the `source-address` critical option. sshd
#                      itself then refuses the cert unless the connection comes
#                      from that address/CIDR. MUST be pre-validated by the
#                      caller (passed verbatim to ssh-keygen -O).
#
# Returns { certificate, serial } where `serial` is the serial the certificate
# carries, in decimal (a string with `openbao`, since it may not fit a native
# signed integer): callers must record that one, not the one they passed.
# On failure, undef or a hashref without `certificate`; `error =>
# 'unavailable'` then means OpenBao could not be reached or refused to sign.
sub _signSshKey {
    my $self = shift;
    return $self->signer eq 'openbao'
      ? $self->_signOpenBao(@_)
      : $self->_signLocal(@_);
}

# HELPER: Sign SSH key using ssh-keygen and the CA private key of the LLNG
# configuration (sshCaSigner = local).
sub _signLocal {
    my ( $self, $userPubKey, $principals, $validityMinutes, $serial, $keyId,
        $opts )
      = @_;
    $opts = {} unless ref $opts eq 'HASH';

    require File::Temp;

    # Create temp directory for key files.
    #
    # SECURITY: this directory holds the UNENCRYPTED CA private key, so it
    # must not outlive the signing operation. `File::Temp::tempdir(CLEANUP
    # => 1)` would only clean up at *program* exit — in a long-lived portal
    # worker (FastCGI/mod_perl) every /ssh/sign would then leave a copy of
    # the CA key in /tmp for the worker's whole lifetime, accumulating
    # without bound. `File::Temp->newdir` ties the removal to the object's
    # destruction instead, i.e. to this sub's scope, including every early
    # `return` and any `die` in between.
    my $tmpobj = File::Temp->newdir();
    my $tmpdir = "$tmpobj";

    # Write CA private key to temp file (convert PEM to OpenSSH format)
    my $caKeyFile = "$tmpdir/ca_key";
    open my $fh, '>', $caKeyFile or do {
        $self->logger->error("SSH CA: Cannot write CA key: $!");
        return undef;
    };
    print $fh $self->sshPrivKey;
    close $fh;
    chmod 0600, $caKeyFile;

    # Write user's public key to temp file
    my $userKeyFile = "$tmpdir/user_key.pub";
    open $fh, '>', $userKeyFile or do {
        $self->logger->error("SSH CA: Cannot write user key: $!");
        return undef;
    };
    print $fh $userPubKey;
    print $fh "\n" unless $userPubKey =~ /\n$/;
    close $fh;

    # Build ssh-keygen command
    my $validitySpec = $opts->{validity} || "+${validityMinutes}m";
    my @cmd = (
        'ssh-keygen',
        '-s', $caKeyFile,                   # CA key
        '-I', $keyId,                       # Key identity
        '-n', join( ',', @$principals ),    # Principals
        '-V', $validitySpec,                # Validity (override via $opts)
        '-z', $serial,                      # Serial number
    );

    # Optional `source-address` critical option: sshd refuses the cert unless
    # the connection originates from this address/CIDR. Used by bastion-cert
    # vouching to pin a cert to the vouching bastion's IP.
    push @cmd, '-O', "source-address=$opts->{source_address}"
      if defined $opts->{source_address} && $opts->{source_address} ne '';

    push @cmd, $userKeyFile;               # User's public key to sign (last)

    $self->logger->debug( "SSH CA: Running: " . join( ' ', @cmd ) );

    # Execute ssh-keygen
    my $output = '';
    my $pid    = open my $pipe, '-|';
    if ( !defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork: $!");
        return undef;
    }
    elsif ( $pid == 0 ) {

        # Child process. _exit rather than exit: exec failed, so this is an
        # environment failure, and the portal worker's END blocks and
        # destructors must not run in the forked child.
        open STDERR, '>&', \*STDOUT;
        exec @cmd or POSIX::_exit(127);
    }
    else {
        # Parent process
        local $/;
        $output = <$pipe>;
        close $pipe;
    }

    my $exitCode = $? >> 8;

    # ssh-keygen is done with the CA key: drop it immediately rather than
    # waiting for $tmpobj's destructor, so the private key spends the
    # shortest possible time on disk.
    unlink $caKeyFile;

    if ( $exitCode != 0 ) {
        $self->logger->error(
            "SSH CA: ssh-keygen failed (exit $exitCode): $output");
        return undef;
    }

    # Read the generated certificate
    my $certFile = "$tmpdir/user_key-cert.pub";
    unless ( -f $certFile ) {
        $self->logger->error("SSH CA: Certificate file not created");
        return undef;
    }

    open $fh, '<', $certFile or do {
        $self->logger->error("SSH CA: Cannot read certificate: $!");
        return undef;
    };
    my $certificate = <$fh>;
    close $fh;
    chomp $certificate;

    return { certificate => $certificate, serial => $serial };
}

# =============================================================================
# OPENBAO SIGNER (sshCaSigner = openbao, issue #476)
# =============================================================================
#
# OpenBao's SSH secrets engine holds the CA private key and signs; the portal
# only holds an AppRole credential limited to one signing role. LLNG keeps
# every decision (principals, validity, source-address, key ID) and checks
# that the certificate it gets back is exactly the one it asked for: a role
# configured too broadly must never silently hand out a broader certificate.
# There is no fallback to a local key: when OpenBao cannot sign, nothing is
# signed.

# Characters allowed in the mount and role path segments. They are pasted
# into the request URL, so anything else (`?`, `#`, `%`, `..`) is refused at
# init rather than escaped into a path nobody meant.
my $BAO_SEGMENTS = qr{\A[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\z};

# Extensions `ssh-keygen -s` grants by default, i.e. what a locally signed
# certificate carries. An OpenBao certificate may carry fewer (the role's
# default_extensions), never another one: `no-touch-required` would for
# instance waive the FIDO touch of an sk- key.
my %BAO_ALLOWED_EXTENSIONS = map { $_ => 1 } qw(
  permit-X11-forwarding
  permit-agent-forwarding
  permit-port-forwarding
  permit-pty
  permit-user-rc
);

# Clock difference tolerated between OpenBao and the portal when checking the
# end of validity of a certificate against the requested TTL: at most 60s
# later than requested (less than a 120s hop TTL), up to 300s sooner (a
# shorter certificate grants less).
use constant SSHCA_BAO_LATE_SKEW  => 60;
use constant SSHCA_BAO_EARLY_SKEW => 300;

# Number of key fields following the nonce in a certificate, per key type:
# the same fields, in the same order, as in the plain public key blob
# (PROTOCOL.certkeys).
my %SSHCA_CERT_KEY_FIELDS = (
    'ssh-ed25519'                        => 1,    # pk
    'sk-ssh-ed25519@openssh.com'         => 2,    # pk, application
    'ssh-rsa'                            => 2,    # e, n
    'ssh-dss'                            => 4,    # p, q, g, y
    'ecdsa-sha2-nistp256'                => 2,    # curve, Q
    'ecdsa-sha2-nistp384'                => 2,
    'ecdsa-sha2-nistp521'                => 2,
    'sk-ecdsa-sha2-nistp256@openssh.com' => 3,    # curve, Q, application
);

# HELPER: read and check the OpenBao parameters. Returns the hashref stored in
# baoConf, or undef (after logging why) when they are incomplete or invalid.
sub _openBaoConf {
    my ($self) = @_;
    my $conf = $self->conf;

    my $str = sub {
        my $v = $conf->{ $_[0] };
        return '' unless defined $v && !ref $v;
        $v =~ s/^\s+|\s+$//g;
        return $v;
    };
    my $fail = sub {
        $self->logger->error("SSH CA: sshCaSigner is openbao but $_[0]");
        return undef;
    };

    # Base URL: scheme and authority, optionally a path prefix (OpenBao
    # behind a reverse proxy). No credentials, query or fragment: they would
    # end up in every request line and in the logs.
    my $url = $str->('sshCaOpenBaoUrl');
    return $fail->('sshCaOpenBaoUrl is not set') unless length $url;
    my $uri = URI->new($url);
    unless ( ( $uri->scheme // '' ) =~ /\Ahttps?\z/
        and $uri->can('host')
        and length( $uri->host // '' )
        and !defined $uri->userinfo
        and !defined $uri->query
        and !defined $uri->fragment
        and $url !~ /[\s\x00-\x1f\x7f]/ )
    {
        return $fail->('sshCaOpenBaoUrl is not a valid http(s) URL');
    }
    my $path = $uri->path // '';
    $path =~ s{/+\z}{};
    $url = $uri->scheme . '://' . $uri->authority . $path;
    $self->logger->warn( 'SSH CA: sshCaOpenBaoUrl is not https, the OpenBao '
          . 'token and the AppRole secret travel in clear' )
      if $uri->scheme eq 'http';

    my $mount = $str->('sshCaOpenBaoMount');
    $mount = 'ssh' unless length $mount;
    my $role         = $str->('sshCaOpenBaoRole');
    my $approleMount = $str->('sshCaOpenBaoAppRoleMount');
    $approleMount = 'approle' unless length $approleMount;
    return $fail->('sshCaOpenBaoRole is not set') unless length $role;
    for (
        [ sshCaOpenBaoMount        => $mount ],
        [ sshCaOpenBaoRole         => $role ],
        [ sshCaOpenBaoAppRoleMount => $approleMount ],
      )
    {
        my ( $name, $v ) = @$_;
        return $fail->("$name contains characters not allowed in a path")
          unless $v =~ $BAO_SEGMENTS
          and !grep { $_ eq '.' || $_ eq '..' } split m{/}, $v;
    }
    return $fail->('sshCaOpenBaoRole must be a single path segment')
      if $role =~ m{/};

    my $roleId = $str->('sshCaOpenBaoRoleId');
    return $fail->('sshCaOpenBaoRoleId is not set') unless length $roleId;

    # Exactly one source for the secret_id. The file and the environment
    # variable keep it out of the LLNG configuration, which every portal node
    # and every configuration backup holds. Several sources would leave the
    # operator guessing which one is used.
    my %secret = (
        value => $str->('sshCaOpenBaoSecretId'),
        file  => $str->('sshCaOpenBaoSecretIdFile'),
        env   => $str->('sshCaOpenBaoSecretIdEnv'),
    );
    my @sources = grep { length $secret{$_} } sort keys %secret;
    return $fail->( 'none of sshCaOpenBaoSecretId, sshCaOpenBaoSecretIdFile '
          . 'and sshCaOpenBaoSecretIdEnv is set' )
      unless @sources;
    return $fail->( 'only one of sshCaOpenBaoSecretId, '
          . 'sshCaOpenBaoSecretIdFile and sshCaOpenBaoSecretIdEnv may be set' )
      if @sources > 1;

    # Read at each login, so that a rotated secret_id is picked up without a
    # configuration reload. Only warn here: the portal may start before the
    # file is deployed.
    $self->logger->warn( "SSH CA: sshCaOpenBaoSecretIdFile $secret{file} "
          . 'is not readable (yet)' )
      if length $secret{file} and !-r $secret{file};
    $self->logger->warn( "SSH CA: environment variable $secret{env} "
          . '(sshCaOpenBaoSecretIdEnv) is not set (yet)' )
      if length $secret{env}
      and !( defined $ENV{ $secret{env} } && length $ENV{ $secret{env} } );

    my $caFile = $str->('sshCaOpenBaoCaFile');
    if ( length $caFile and !-r $caFile ) {
        return $fail->("sshCaOpenBaoCaFile $caFile is not readable");
    }

    return {
        url          => $url,
        mount        => $mount,
        role         => $role,
        approleMount => $approleMount,
        roleId       => $roleId,
        secretId     => $secret{value},
        secretIdFile => $secret{file},
        secretIdEnv  => $secret{env},
        caFile       => $caFile,

        # Every portal worker blocks on this call: keep it short.
        timeout => $self->_positiveIntConf( 'sshCaOpenBaoTimeout', 5 ) || 5,
    };
}

# HELPER: a string as characters. A string flagged as characters, or pure
# ASCII, is returned as is. Unflagged bytes >= 0x80 are UTF-8 when they decode
# as such (what some backends store in the session); otherwise they already
# are Latin-1 characters.
sub _toChars {
    my ($s) = @_;
    return $s if !defined $s or utf8::is_utf8($s) or $s !~ /[\x80-\xff]/;
    my $chars = eval { Encode::decode( 'UTF-8', "$s", Encode::FB_CROAK ) };
    return defined $chars ? $chars : $s;
}

# HELPER: random hexadecimal string of $bytes bytes (key ID nonce).
sub _nonceHex {
    my ($bytes) = @_;
    my $raw = eval { require Crypt::URandom; Crypt::URandom::urandom($bytes) };
    $raw = join '', map { chr int rand 256 } 1 .. $bytes
      unless defined $raw && length $raw == $bytes;
    return unpack 'H*', $raw;
}

# HELPER: send one request to OpenBao. $path is relative to /v1/. Returns the
# HTTP::Response; LWP turns connection failures and timeouts into a 5xx
# response, so the caller only has to look at the status.
sub _baoRequest {
    my ( $self, $method, $path, $body, $token ) = @_;
    require HTTP::Request;

    # Everything in the eval: HTTP::Message croaks on a body that is not
    # bytes, and a die here would escape through the route handler.
    my $resp = eval {
        my $req =
          HTTP::Request->new( $method, $self->baoConf->{url} . "/v1/$path" );
        $req->header( 'X-Vault-Token' => $token ) if defined $token;
        if ( defined $body ) {

            # UTF-8 bytes. to_json() returns characters: a key ID or a
            # principal with "é" went out as Latin-1 (OpenBao then reads
            # U+FFFD), and one with "ł" made HTTP::Message die.
            $req->header( 'Content-Type' => 'application/json' );
            $req->content( JSON->new->utf8->canonical->encode($body) );
        }
        $self->ua->request($req);
    };
    unless ($resp) {
        require HTTP::Response;
        my $err = $@ || 'no response';
        $err =~ s/[\r\n]+/ /g;
        $resp = HTTP::Response->new( 500, "Request failed: $err" );
    }
    return $resp;
}

# HELPER: decode an OpenBao JSON answer. Returns a hashref, or undef when the
# body is not a JSON object.
sub _baoJson {
    my ( $self, $resp ) = @_;
    my $data = eval { JSON::decode_json( $resp->content // '' ) };
    return ref $data eq 'HASH' ? $data : undef;
}

# HELPER: one-line description of a failed OpenBao answer for the logs: the
# status line, and OpenBao's `errors` messages when it sent some. Never the
# body as such, which could carry a token.
sub _baoFailure {
    my ( $self, $resp ) = @_;
    my $msg  = $resp->status_line;
    my $data = $self->_baoJson($resp);
    if ( $data and ref $data->{errors} eq 'ARRAY' ) {
        my $errors = join '; ', grep { defined && !ref } @{ $data->{errors} };
        $errors =~ s/[\x00-\x1f\x7f]+/ /g;
        $errors = substr( $errors, 0, 300 );
        $msg .= " ($errors)" if length $errors;
    }
    $msg =~ s/[\x00-\x1f\x7f]+/ /g;
    return $msg;
}

# HELPER: the AppRole secret_id, from wherever the configuration says.
sub _baoSecretId {
    my ($self) = @_;
    my $bao = $self->baoConf;
    return $bao->{secretId} if length $bao->{secretId};
    if ( length $bao->{secretIdEnv} ) {
        my $v = $ENV{ $bao->{secretIdEnv} };
        $v = '' unless defined $v;
        $v =~ s/^\s+|\s+$//g;
        return $v if length $v;
        $self->logger->error( 'SSH CA: environment variable '
              . "$bao->{secretIdEnv} (sshCaOpenBaoSecretIdEnv) is empty" );
        return undef;
    }
    my $file = $bao->{secretIdFile};
    my $fh;
    unless ( open $fh, '<', $file ) {
        $self->logger->error("SSH CA: cannot read $file: $!");
        return undef;
    }
    local $/;
    my $v = <$fh>;
    close $fh;
    $v = '' unless defined $v;
    $v =~ s/^\s+|\s+$//g;
    unless ( length $v ) {
        $self->logger->error("SSH CA: $file holds no AppRole secret_id");
        return undef;
    }
    return $v;
}

# HELPER: AppRole login. Caches the token and its expiry on the plugin object,
# i.e. per worker. Returns the token, or undef after logging why.
sub _baoLogin {
    my ($self) = @_;
    my $bao = $self->baoConf;

    $self->_baoToken(undef);
    $self->_baoTokenExp(0);

    my $secretId = $self->_baoSecretId;
    return undef unless defined $secretId;

    my $resp = $self->_baoRequest(
        'POST',
        "auth/$bao->{approleMount}/login",
        { role_id => $bao->{roleId}, secret_id => $secretId }
    );
    unless ( $resp->is_success ) {
        $self->logger->error( 'SSH CA: OpenBao AppRole login failed: '
              . $self->_baoFailure($resp) );
        return undef;
    }

    # Every level is checked: a proxy answering 200 with an HTML page, or an
    # unexpected shape, must not die or end up in a request header.
    my $data = $self->_baoJson($resp);
    my $auth = $data ? $data->{auth} : undef;
    my $token =
      ref $auth eq 'HASH' && defined $auth->{client_token}
      ? $auth->{client_token}
      : undef;
    unless ( defined $token and !ref $token and $token =~ /\A[\x21-\x7e]+\z/ ) {
        $self->logger->error(
            'SSH CA: OpenBao AppRole login: unexpected response');
        return undef;
    }

    # Unknown or absent lease: treat the token as already expiring, so the
    # next signature logs in again rather than using a dead token.
    my $lease = $auth->{lease_duration};
    $lease = 0
      unless defined $lease && !ref $lease && $lease =~ /\A[0-9]{1,10}\z/;

    $self->_baoToken($token);
    $self->_baoTokenExp( time + $lease );
    return $token;
}

# HELPER: a usable token: the cached one while it has more than 30s left,
# otherwise (or with $force) a fresh login.
sub _baoTokenGet {
    my ( $self, $force ) = @_;
    return $self->_baoToken
      if !$force
      and defined $self->_baoToken
      and $self->_baoTokenExp - time >= 30;
    return $self->_baoLogin;
}

# HELPER: compare OpenBao's CA public key with the pinned one, at init. Only
# logs: a failure to reach OpenBao must not keep the portal from starting.
sub _checkOpenBaoPublicKey {
    my ($self) = @_;
    my $bao    = $self->baoConf;
    my $resp   = $self->_baoRequest( 'GET', "$bao->{mount}/public_key" );
    unless ( $resp->is_success ) {
        $self->logger->warn( 'SSH CA: could not fetch the CA public key from '
              . 'OpenBao to check it against keys/'
              . $self->conf->{sshCaKeyRef} . ': '
              . $self->_baoFailure($resp) );
        return undef;
    }
    my ($bao_b64) = ( $resp->content // '' ) =~ /\A\s*\S+\s+(\S+)/;
    my ($pin_b64) = $self->sshPubKey         =~ /\A\s*\S+\s+(\S+)/;
    if (    defined $bao_b64
        and defined $pin_b64
        and decode_base64($bao_b64) eq decode_base64($pin_b64) )
    {
        $self->logger->debug('SSH CA: OpenBao CA public key matches the pin');
        return 1;
    }
    $self->logger->error( 'SSH CA: the CA public key of OpenBao mount '
          . "'$bao->{mount}' differs from keys/"
          . $self->conf->{sshCaKeyRef}
          . '/keyPublic: every certificate it signs will be refused' );
    return 0;
}

# HELPER: Sign SSH key through OpenBao's SSH secrets engine
# (sshCaSigner = openbao). Same arguments as _signSshKey; $serial is ignored.
sub _signOpenBao {
    my ( $self, $userPubKey, $principals, $validityMinutes, undef, $keyId,
        $opts )
      = @_;
    $opts = {} unless ref $opts eq 'HASH';
    my $bao         = $self->baoConf;
    my $unavailable = { error => 'unavailable' };
    my $invalid     = { error => 'invalid' };

    unless ($bao) {
        $self->logger->error('SSH CA: OpenBao signer is not configured');
        return $unavailable;
    }

    # TTL: the explicit validity spec when given (hop certificates, "+120s"),
    # otherwise the validity in minutes. Kept in seconds for the check below.
    my ( $ttl, $ttlSpec );
    if ( defined $opts->{validity} && $opts->{validity} ne '' ) {
        unless ( $opts->{validity} =~ /\A\+([0-9]{1,9})([sm])\z/ ) {
            $self->logger->error( 'SSH CA: validity spec not supported by '
                  . "the OpenBao signer: $opts->{validity}" );
            return $invalid;
        }
        $ttl     = $2 eq 'm' ? $1 * 60 : $1 + 0;
        $ttlSpec = "${ttl}s";
    }
    elsif ( defined $validityMinutes && $validityMinutes =~ /\A[0-9]{1,9}\z/ ) {
        $ttl     = $validityMinutes * 60;
        $ttlSpec = ( $validityMinutes + 0 ) . 'm';
    }
    unless ($ttl) {
        $self->logger->error('SSH CA: no usable validity to sign with');
        return $invalid;
    }

    # The submitted key, as the blob the certificate must certify.
    my ( $keyType, $keyB64 ) =
      ( $userPubKey // '' ) =~ /\A\s*(\S+)\s+([A-Za-z0-9+\/]+={0,2})(?:\s|\z)/;
    my $keyBlob = defined $keyB64 ? decode_base64($keyB64) : '';
    unless ( length $keyBlob ) {
        $self->logger->error('SSH CA: cannot decode the key to sign');
        return $invalid;
    }

    # Key ID and principals as character strings: they come from session
    # attributes, which are decoded strings with some backends and UTF-8
    # bytes with others. They are sent as UTF-8 (_baoRequest) and the
    # certificate carries UTF-8 bytes, compared below with their encoding.
    # Duplicates are dropped: the certificate must then carry each principal
    # exactly once.
    $keyId = _toChars($keyId);
    my ( %seen, @principals );
    for ( @{ $principals || [] } ) {
        my $p = _toChars($_);
        push @principals, $p unless $seen{$p}++;
    }

    # valid_principals is a comma-separated list: a comma inside a principal
    # would make OpenBao certify two. The callers never produce one, refuse
    # rather than trust it.
    if ( !@principals or grep { !length || /[,\x00-\x1f\x7f]/ } @principals ) {
        $self->logger->error(
            'SSH CA: refusing to sign with unusable principals');
        return $invalid;
    }

    my $source =
      defined $opts->{source_address} && $opts->{source_address} ne ''
      ? $opts->{source_address}
      : undef;

    my $body = {
        public_key       => "$keyType $keyB64",
        valid_principals => join( ',', @principals ),
        cert_type        => 'user',
        key_id           => $keyId,
        ttl              => $ttlSpec,
        (
            $source
            ? ( critical_options => { 'source-address' => $source } )
            : ()
        ),
    };

    my $path  = "$bao->{mount}/sign/$bao->{role}";
    my $token = $self->_baoTokenGet;
    return $unavailable unless defined $token;
    $self->logger->debug(
        "SSH CA: asking OpenBao to sign ($path, key_id=$keyId)");
    my $resp = $self->_baoRequest( 'POST', $path, $body, $token );

    # 403: the token was revoked, has used up its uses, or expired earlier
    # than announced. Log in again, once, and retry once.
    if ( $resp->code == 403 ) {
        $self->logger->info(
            'SSH CA: OpenBao refused the token, logging in again');
        $token = $self->_baoTokenGet(1);
        return $unavailable unless defined $token;
        $resp = $self->_baoRequest( 'POST', $path, $body, $token );
    }
    unless ( $resp->is_success ) {
        $self->_baoToken(undef) if $resp->code == 403;
        $self->logger->error(
            'SSH CA: OpenBao did not sign: ' . $self->_baoFailure($resp) );
        return $unavailable;
    }

    # From here on, OpenBao answered: anything unexpected is refused (500),
    # never handed out.
    my $data = $self->_baoJson($resp);
    $data = $data->{data} if $data;
    unless (ref $data eq 'HASH'
        and defined $data->{serial_number}
        and !ref $data->{serial_number}
        and defined $data->{signed_key}
        and !ref $data->{signed_key} )
    {
        $self->logger->error('SSH CA: OpenBao sign: unexpected response');
        return $invalid;
    }
    my ( $certType, $certB64 ) = $data->{signed_key} =~
      m{\A\s*(\S+-cert-v01\@openssh\.com)\s+([A-Za-z0-9+/]+={0,2})\s*\z};
    my $cert =
      defined $certB64
      ? $self->_parseSshCert( decode_base64($certB64) )
      : undef;
    unless ( $cert and $cert->{type} eq $certType ) {
        $self->logger->error(
            'SSH CA: OpenBao returned an unparsable certificate');
        return $invalid;
    }

    # The certificate must be exactly the one requested.
    my ($pinB64) = ( $self->sshPubKey // '' ) =~ /\A\s*\S+\s+(\S+)/;
    my $now      = time;
    my @want     = sort map { Encode::encode_utf8($_) } @principals;
    my @got      = sort @{ $cert->{principals} };
    my $crit     = $cert->{critical_options};
    my @problems;
    push @problems, 'not a user certificate' unless $cert->{cert_type} == 1;
    push @problems, 'it certifies another key'
      unless $cert->{key_blob} eq $keyBlob;
    push @problems, 'it is signed by another CA than the pinned one'
      unless defined $pinB64
      and $cert->{signature_key} eq decode_base64($pinB64);
    push @problems, 'its key ID differs'
      unless $cert->{key_id} eq Encode::encode_utf8($keyId);

    # Same list, element by element: a principal missing, added or repeated
    # is a difference.
    push @problems, 'its principals differ'
      unless @want == @got
      and !grep { $want[$_] ne $got[$_] } 0 .. $#want;
    my $gotSource = $crit->{'source-address'};
    push @problems, 'its source-address differs'
      unless ( !defined $source && !defined $gotSource )
      or (  defined $source
        and defined $gotSource
        and $gotSource eq $source );
    push @problems, 'it carries unexpected critical options'
      if grep { $_ ne 'source-address' } keys %$crit;
    push @problems, 'it carries unexpected extensions'
      if grep { !$BAO_ALLOWED_EXTENSIONS{$_} } keys %{ $cert->{extensions} };

    # Tight on the late side (a hop certificate lives 120s), lenient on the
    # early side: a certificate ending sooner than requested is narrower.
    push @problems, 'its validity does not match the requested TTL'
      if $cert->{valid_before} > $now + $ttl + SSHCA_BAO_LATE_SKEW
      or $cert->{valid_before} < $now + $ttl - SSHCA_BAO_EARLY_SKEW;

    # The serial goes into the records and the KRL. Read it from the
    # certificate (that is what sshd and the KRL see), cross-check it with
    # OpenBao's answer, and keep it in decimal. 0 cannot be revoked by serial
    # in a KRL, so a certificate carrying it could never be revoked.
    my $serial    = $cert->{serial};
    my $announced = $data->{serial_number};
    if ( $announced =~ /\A(?:0x)?([0-9a-fA-F]{1,16})\z/ ) {
        require Math::BigInt;
        push @problems, 'its serial differs from serial_number'
          unless Math::BigInt->from_hex($1)->bstr eq $serial;
    }
    else {
        push @problems, 'serial_number is not a 64-bit hexadecimal number';
    }
    push @problems, 'its serial is unusable'
      unless $self->_validSerial($serial)
      and $serial ne '0';

    if (@problems) {
        $self->logger->error( 'SSH CA: refusing the certificate signed by '
              . "OpenBao for key_id=$keyId: "
              . join( ', ', @problems ) );
        return $invalid;
    }

    return { certificate => "$certType $certB64", serial => $serial };
}

# HELPER: parse an OpenSSH certificate blob (PROTOCOL.certkeys):
#   string type, string nonce, <key fields>, uint64 serial, uint32 type,
#   string key id, string valid principals, uint64 valid after,
#   uint64 valid before, string critical options, string extensions,
#   string reserved, string signature key, string signature
# Returns undef unless the whole blob parses (no trailing bytes), otherwise a
# hashref: type, key_type, key_blob (the certified key as a plain public key
# blob), serial (decimal string), cert_type, key_id, principals (arrayref),
# valid_after, valid_before, critical_options and extensions (hashrefs, the
# value of an option being its inner string, '' when it has none),
# signature_key (blob) and signature.
#
# The signature itself is not verified: the signature key is compared with
# the pinned CA key, and sshd refuses a certificate whose signature does not
# match it.
sub _parseSshCert {
    my ( $self, $blob ) = @_;
    return undef unless defined $blob && length $blob;

    my $pos  = 0;
    my $read = sub {
        my $n = shift;
        return undef if $n > length($blob) - $pos;
        my $v = substr( $blob, $pos, $n );
        $pos += $n;
        return $v;
    };
    my $string = sub {
        my $l = $read->(4);
        return defined $l ? $read->( unpack 'N', $l ) : undef;
    };

    my %c;
    defined( $c{type} = $string->() ) or return undef;
    my ($keyType) = $c{type} =~ /\A(.+)-cert-v01\@openssh\.com\z/
      or return undef;
    $keyType .= '@openssh.com' if $keyType =~ /\Ask-/;
    my $fields = $SSHCA_CERT_KEY_FIELDS{$keyType} or return undef;
    $c{key_type} = $keyType;

    defined $string->() or return undef;    # nonce
    my $start = $pos;
    for ( 1 .. $fields ) { defined $string->() or return undef }
    $c{key_blob} =
        pack( 'N', length $keyType )
      . $keyType
      . substr( $blob, $start, $pos - $start );

    my $serial = $read->(8) // return undef;
    require Math::BigInt;
    $c{serial} = Math::BigInt->from_hex( unpack 'H*', $serial )->bstr;
    my $certType = $read->(4) // return undef;
    $c{cert_type} = unpack 'N', $certType;
    defined( $c{key_id} = $string->() ) or return undef;
    my $principals = $string->() // return undef;
    for my $k (qw(valid_after valid_before)) {
        my $v = $read->(8) // return undef;
        my ( $hi, $lo ) = unpack 'NN', $v;
        $c{$k} = $hi * 4294967296 + $lo;
    }
    my $critical   = $string->() // return undef;
    my $extensions = $string->() // return undef;
    defined $string->() or return undef;    # reserved
    defined( $c{signature_key} = $string->() ) or return undef;
    defined( $c{signature}     = $string->() ) or return undef;
    return undef unless $pos == length $blob;

    $c{principals}       = _sshStringList($principals)   // return undef;
    $c{critical_options} = _sshOptionMap( $critical, 1 ) // return undef;
    $c{extensions}       = _sshOptionMap($extensions)    // return undef;
    return \%c;
}

# HELPER: split a buffer made of consecutive SSH strings. Undef when it does
# not split exactly.
sub _sshStringList {
    my ($buf) = @_;
    my ( $pos, @list ) = (0);
    while ( $pos < length $buf ) {
        return undef if length($buf) - $pos < 4;
        my $l = unpack 'N', substr( $buf, $pos, 4 );
        $pos += 4;
        return undef if $l > length($buf) - $pos;
        push @list, substr( $buf, $pos, $l );
        $pos += $l;
    }
    return \@list;
}

# HELPER: decode a certificate's critical options or extensions: pairs of
# (string name, string data). With $inner, a non-empty data is itself one SSH
# string (critical options), which is returned. Undef on any framing error or
# duplicate name.
sub _sshOptionMap {
    my ( $buf, $inner ) = @_;
    my $list = _sshStringList($buf) or return undef;
    return undef if @$list % 2;
    my %map;
    while ( my ( $name, $data ) = splice @$list, 0, 2 ) {
        return undef if exists $map{$name};
        if ( $inner and length $data ) {
            my $v = _sshStringList($data);
            return undef unless $v and @$v == 1;
            $data = $v->[0];
        }
        $map{$name} = $data;
    }
    return \%map;
}

# HELPER: Convert PEM private key to OpenSSH format
sub _pemToOpenSSHPrivateKey {
    my ( $self, $pemKey ) = @_;

    # First, try to detect if it's already in OpenSSH format
    if ( $pemKey =~ /^-----BEGIN OPENSSH PRIVATE KEY-----/ ) {
        return $pemKey;
    }

    # RSA keys in traditional format - ssh-keygen can read these directly
    if ( $pemKey =~ /BEGIN RSA PRIVATE KEY/ ) {
        return $pemKey;
    }

    # For Ed25519 PEM keys, we need to convert to OpenSSH format
    # because ssh-keygen cannot read Ed25519 PEM keys
    if (   $pemKey =~ /BEGIN PRIVATE KEY/
        || $pemKey =~ /BEGIN ED25519 PRIVATE KEY/ )
    {
        eval {
            require Crypt::PK::Ed25519;
            require MIME::Base64;

            my $pk = Crypt::PK::Ed25519->new( \$pemKey );

            # Get raw keys
            my $privRaw = $pk->export_key_raw('private');    # 32 bytes
            my $pubRaw  = $pk->export_key_raw('public');     # 32 bytes

            # Build OpenSSH private key format
            my $opensshKey =
              $self->_buildOpenSSHPrivateKey( $privRaw, $pubRaw, '' );
            return $opensshKey if $opensshKey;
        };
        if ($@) {
            $self->logger->error("SSH CA: Failed to convert Ed25519 key: $@");
        }
    }

    # EC keys - ssh-keygen can typically read these
    if ( $pemKey =~ /BEGIN EC PRIVATE KEY/ ) {
        return $pemKey;
    }

    # Fallback: return as-is and let ssh-keygen try
    return $pemKey;
}

# HELPER: Build OpenSSH private key format from raw Ed25519 key material
sub _buildOpenSSHPrivateKey {
    my ( $self, $privRaw, $pubRaw, $comment ) = @_;

    require MIME::Base64;

    # OpenSSH private key format for Ed25519 (unencrypted):
    # - Magic: "openssh-key-v1\0"
    # - Cipher name: "none" (string with length prefix)
    # - KDF name: "none" (string with length prefix)
    # - KDF options: empty string (length 0)
    # - Number of keys: 1 (uint32)
    # - Public key section (length-prefixed)
    # - Private/encrypted section (length-prefixed)

    my $keytype = 'ssh-ed25519';

    # Build public key blob
    my $pubBlob = pack( 'N', length($keytype) ) . $keytype;
    $pubBlob .= pack( 'N', length($pubRaw) ) . $pubRaw;

    # Build private section
    # Generate random check integers (must match)
    my $checkInt = int( rand(0xFFFFFFFF) );

    my $privSection = '';
    $privSection .= pack( 'N', $checkInt );    # check-int 1
    $privSection .= pack( 'N', $checkInt );    # check-int 2 (must match)

    # Key type
    $privSection .= pack( 'N', length($keytype) ) . $keytype;

    # Public key (32 bytes)
    $privSection .= pack( 'N', length($pubRaw) ) . $pubRaw;

    # Secret buffer: private key (32 bytes) + public key (32 bytes) = 64 bytes
    my $secretBuf = $privRaw . $pubRaw;
    $privSection .= pack( 'N', length($secretBuf) ) . $secretBuf;

    # Comment
    $comment //= '';
    $privSection .= pack( 'N', length($comment) ) . $comment;

    # Padding to 8-byte block size (for "none" cipher)
    my $blockSize = 8;
    my $padLen    = $blockSize - ( length($privSection) % $blockSize );
    $padLen = 0 if $padLen == $blockSize;
    for my $i ( 1 .. $padLen ) {
        $privSection .= chr($i);
    }

    # Build full key
    my $key = '';

    # Magic header
    $key .= "openssh-key-v1\0";

    # Cipher name: "none"
    my $cipher = 'none';
    $key .= pack( 'N', length($cipher) ) . $cipher;

    # KDF name: "none"
    my $kdf = 'none';
    $key .= pack( 'N', length($kdf) ) . $kdf;

    # KDF options: empty
    $key .= pack( 'N', 0 );

    # Number of keys
    $key .= pack( 'N', 1 );

    # Public key section
    $key .= pack( 'N', length($pubBlob) ) . $pubBlob;

    # Private section
    $key .= pack( 'N', length($privSection) ) . $privSection;

    # Encode as PEM
    my $b64    = MIME::Base64::encode_base64( $key, '' );
    my $pem    = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    my $offset = 0;
    while ( $offset < length($b64) ) {
        $pem .= substr( $b64, $offset, 70 ) . "\n";
        $offset += 70;
    }
    $pem .= "-----END OPENSSH PRIVATE KEY-----\n";

    return $pem;
}

# HELPER: Convert PEM public key to SSH format
sub _pemToSshPublicKey {
    my ( $self, $pemKey, $comment ) = @_;

    require MIME::Base64;

    # Already an OpenSSH public key line, which is what OpenBao serves on
    # /v1/<mount>/public_key (issue #476): pinning it does not require a
    # conversion to PEM, which ssh-keygen cannot do for every key type. Taken
    # as is once its blob parses as a key of the type it announces.
    if ( defined $pemKey
        and $pemKey =~
m{\A\s*((?:ssh|ecdsa-sha2)-[\w-]+)\s+([A-Za-z0-9+/]+={0,2})(?:[ \t]+([^\r\n]*?))?\s*\z}
      )
    {
        my ( $type, $b64, $keyComment ) = ( $1, $2, $3 );
        unless ( $self->_parseSshPubKey("$type $b64") ) {
            $self->logger->error(
                "SSH CA: the CA public key is not a valid $type key");
            return undef;
        }
        $keyComment = "LLNG-SSH-CA-$comment"
          unless defined $keyComment && length $keyComment;
        return "$type $b64 $keyComment\n";
    }

    my $sshKey;

    # Try Ed25519 first
    eval {
        require Crypt::PK::Ed25519;
        my $pk     = Crypt::PK::Ed25519->new( \$pemKey );
        my $rawKey = $pk->export_key_raw('public');

        # Build SSH format: string "ssh-ed25519" + string <32 bytes key>
        my $keyType = 'ssh-ed25519';
        my $blob =
            pack( 'N', length($keyType) )
          . $keyType
          . pack( 'N', length($rawKey) )
          . $rawKey;

        $sshKey = "$keyType " . MIME::Base64::encode_base64( $blob, '' );
    };

    # Try RSA if Ed25519 failed
    if ( $@ || !$sshKey ) {
        eval {
            require Crypt::PK::RSA;
            my $pk = Crypt::PK::RSA->new( \$pemKey );

            if ( $pk->can('export_key_openssh') ) {
                $sshKey = $pk->export_key_openssh;
            }
            else {
                # Fallback: use ssh-keygen to convert PEM public key
                # (`newdir` so the scratch dir dies with this scope, not
                # with the worker — see _signSshKey)
                require File::Temp;
                my $tmpobj  = File::Temp->newdir();
                my $keyFile = "$tmpobj/key.pub";
                open my $fh, '>', $keyFile or die "Cannot write: $!";
                print $fh $pemKey;
                close $fh;
                $sshKey = `ssh-keygen -i -m PKCS8 -f $keyFile 2>&1`;
                my $exit = $? >> 8;
                if ( $exit != 0 ) {
                    $self->logger->error(
                        "SSH CA: ssh-keygen -i failed (exit $exit): $sshKey");
                    $sshKey = undef;
                }
                else {
                    chomp $sshKey;
                    $sshKey = undef unless $sshKey;
                }
            }
        };
    }

    unless ($sshKey) {
        $self->logger->error("SSH CA: Failed to convert key to SSH format: $@");
        return undef;
    }

    # Add comment (SSH key has format: type base64 [comment])
    chomp($sshKey);
    my @parts = split /\s+/, $sshKey;
    if ( @parts == 2 ) {

        # No comment yet, add one
        $sshKey .= " LLNG-SSH-CA-$comment";
    }

    return "$sshKey\n";
}

# GET /ssh/mycerts - List current user's certificates
sub sshMyCerts {
    my ( $self, $req ) = @_;

    my $sshCerts = $self->_certsFromData( $req->userData );

    my $now     = time();
    my $useData = $self->_liveData($req);
    my @certs;
    for my $cert (@$sshCerts) {
        my $v = $self->_certView( $useData, $cert, $now );

        # Revocation details stay on the administration side.
        delete @$v{qw(revoked_by revoke_reason)};
        push @certs, $v;
    }

    # Sort by issued_at descending (newest first)
    @certs =
      sort { ( $b->{issued_at} || 0 ) <=> ( $a->{issued_at} || 0 ) } @certs;

    return $self->p->sendJSONresponse( $req, { certificates => \@certs } );
}

# POST /ssh/myrevoke - User revokes one of their own certificates.
# The certificate record is kept in the session with `revoked_at` set so the
# user's list keeps showing it; the serial is immediately published in the
# KRL. Note: re-signing the same key later supersedes and removes the record
# (see _storeCertificate); the KRL retains all revoked serials regardless.
sub sshMyCertRevoke {
    my ( $self, $req ) = @_;

    my ( $body, $bail ) = $self->_jsonBodyOrReject( $req, 'SSH myrevoke' );
    return $bail if $bail;
    my $serial = $body->{serial};

    # A JSON boolean stringifies to "1" and could match a certificate serial,
    # as the broker path did (#435). Refuse references like /ssh/revoke does.
    if ( ref $serial ) {
        return $self->p->sendError( $req, 'serial must be a string', 400 );
    }
    unless ( defined $serial && $serial ne '' ) {
        return $self->p->sendError( $req, 'serial required', 400 );
    }

    # A corrupted legacy array would give us a partial view of the user's
    # certificates, and answering "not found" on it would look like a
    # successful no-op — refuse instead.
    unless ( defined $self->_legacyCerts( $req->userData ) ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Corrupted certificate data' },
            code => 500
        );
    }
    my $sshCerts = $self->_certsFromData( $req->userData );

    my $user =
         $req->userData->{ $self->conf->{whatToTrace} || 'uid' }
      || $req->userData->{uid}
      || $req->user
      || 'unknown';

    my $target;
    for my $cert (@$sshCerts) {
        if ( ( $cert->{serial} || '' ) eq $serial ) {
            if ( $cert->{revoked_at} ) {
                return $self->p->sendJSONresponse(
                    $req,
                    { error => 'Certificate already revoked' },
                    code => 400
                );
            }

            # Its serial went into the KRL when it was replaced.
            if ( $cert->{superseded_at} ) {
                return $self->p->sendJSONresponse(
                    $req,
                    { error => 'Certificate already superseded' },
                    code => 400
                );
            }
            $cert->{revoked_at}    = time();
            $cert->{revoked_by}    = $user;
            $cert->{revoke_reason} = 'self-revocation';
            $target                = $cert;
            last;
        }
    }
    unless ($target) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Certificate not found' },
            code => 404
        );
    }

    my %upd;
    $self->_drainLegacyCerts( $req->userData, \%upd );
    if ( my $k = $self->_certKey($target) ) {
        $upd{$k} = to_json($target);
    }
    $self->p->updatePersistentSession( $req, \%upd );
    my $krlOk = $self->_updateKrl($serial);
    $self->_publishRevoke( $req, $serial );

    $self->logger->info( "SSH CA: Self-revocation by '$user': "
          . "serial=$serial, key_id=$target->{key_id}" );

    $self->p->auditLog(
        $req,
        code       => 'SSH_CERT_SELF_REVOKED',
        user       => $user,
        message    => "SSH certificate self-revoked by '$user'",
        serial     => $serial,
        key_id     => $target->{key_id},
        label      => $target->{label},
        krl_update => $krlOk ? 'success' : 'failed',
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            result      => 1,
            serial      => $serial,
            key_id      => $target->{key_id},
            revoked_at  => $target->{revoked_at},
            krl_updated => $krlOk ? JSON::true : JSON::false,
        }
    );
}

# =============================================================================
# ADMIN INTERFACE METHODS
# =============================================================================

# HELPER: default-deny guard shared by the three administration endpoints.
#
# Returns a ready-to-return 403 response when the caller is not allowed to
# administrate the SSH CA, and undef when access is granted. `adminRule` is
# always a code ref (init() installs a constant-false sub when
# `sshCaAdminRule` is unset or fails to compile), so an unconfigured or
# misconfigured portal denies.
#
# sendError() already negotiates the representation: JSON for the
# XHR-driven /ssh/certs and /ssh/revoke, HTML for /ssh/admin.
sub _forbidNonAdmin {
    my ( $self, $req ) = @_;

    my $rule = $self->adminRule;
    return undef if $rule && $rule->( $req, $req->userData );

    my $whatToTrace = $self->conf->{whatToTrace} || 'uid';
    my $user =
         $req->userData->{$whatToTrace}
      || $req->userData->{uid}
      || $req->user
      || 'unknown';
    my $uri = $req->env->{REQUEST_URI} // '';

    $self->userLogger->warn(
        "SSH CA: user '$user' is not allowed to administrate the SSH CA "
          . "(denied on $uri)" );
    $self->p->auditLog(
        $req,
        code    => 'SSH_CA_ADMIN_DENIED',
        user    => $user,
        message => "SSH CA administration denied for '$user'",
        uri     => $uri,
    );

    return $self->p->sendError( $req, 'Forbidden', 403 );
}

# GET /ssh/admin - Display the revocation interface
# Restricted by the sshCaAdminRule configuration parameter (default: deny)
sub sshAdminInterface {
    my ( $self, $req ) = @_;

    if ( my $denied = $self->_forbidNonAdmin($req) ) { return $denied }

    return $self->p->sendHtml( $req, 'sshcaadmin' );
}

# GET /ssh/certs - List/search certificates from persistent sessions
# Restricted by the sshCaAdminRule configuration parameter (default: deny)
sub sshCertsList {
    my ( $self, $req ) = @_;

    if ( my $denied = $self->_forbidNonAdmin($req) ) { return $denied }

    # Get search parameters
    my $userFilter   = $req->param('user')   || '';
    my $serialFilter = $req->param('serial') || '';
    my $keyIdFilter  = $req->param('key_id') || '';
    my $statusFilter = $req->param('status') || '';    # see _certStatus

    # Last activity (issue #455): `never` (never used), `within:<seconds>`
    # (used in the last <seconds>) or `idle:<seconds>` (neither used nor
    # issued in the last <seconds>: a certificate issued a minute ago is not
    # idle yet). Anything else is a client error rather than "no filter",
    # which would list everything an administrator meant to narrow down.
    my $activity = $req->param('activity') // '';
    my ( $actKind, $actSecs ) = ( '', 0 );
    if ( $activity ne '' ) {
        if ( $activity eq 'never' ) {
            $actKind = 'never';
        }
        elsif ( $activity =~ /\A(within|idle):([0-9]{1,10})\z/ ) {
            ( $actKind, $actSecs ) = ( $1, $2 + 0 );
        }
        else {
            return $self->p->sendError( $req, 'Invalid activity filter',
                400 );
        }
    }

    # Sort order: `issued` (newest first, the default) or `last_used` (most
    # recently used first, never-used certificates last).
    my $sort = $req->param('sort') || 'issued';
    unless ( $sort eq 'issued' or $sort eq 'last_used' ) {
        return $self->p->sendError( $req, 'Invalid sort order', 400 );
    }

    # Pagination: bound below as well as above. `int()` alone turned a
    # negative limit into a negative `splice` length (which silently drops
    # the tail of the list instead of the head) and a non-numeric value into
    # 0 results, so only a plain non-negative integer is honoured here.
    my $limit  = $req->param('limit');
    my $offset = $req->param('offset');
    $limit  = ( defined $limit  && $limit  =~ /\A[0-9]+\z/ ) ? $limit + 0 : 100;
    $offset = ( defined $offset && $offset =~ /\A[0-9]+\z/ ) ? $offset + 0 : 0;

    $limit = 1000 if $limit > 1000;

    # Search in persistent sessions
    my $moduleOptions = {
        backend => $self->conf->{persistentStorage}
          || $self->conf->{globalStorage},
        %{
                 $self->conf->{persistentStorageOptions}
              || $self->conf->{globalStorageOptions}
              || {}
        },
    };

    # No field restriction: certificates live one per key
    # ($CERT_PREFIX.<fingerprint>), whose names are not known in advance.
    #
    # The core loaded whole sessions for this search anyway (searchOnExpr
    # falls back to get_key_from_all_sessions); what changes is that the
    # result now RETAINS them for the length of the scan instead of a few
    # named fields. Fine at the scale this endpoint serves — an administrator
    # listing certificates — but it is the line to look at first if a large
    # fleet makes /ssh/certs heavy.
    my $res =
      Lemonldap::NG::Common::Apache::Session->searchOnExpr( $moduleOptions,
        '_session_kind', 'Persistent' );

    my @certs;
    my $now = time();

    for my $sessionId ( keys %{ $res || {} } ) {
        my $session = $res->{$sessionId};

        my $user     = $session->{_session_uid} || '';
        my $sshCerts = $self->_certsFromData($session);

        # Skip sessions holding no certificate at all
        next unless @$sshCerts;

        # Apply user filter at session level
        if ( $userFilter && $user !~ /\Q$userFilter\E/i ) {
            next;
        }

        for my $cert (@$sshCerts) {

            # Apply filters
            if ( $serialFilter && $cert->{serial} ne $serialFilter ) {
                next;
            }
            if ( $keyIdFilter
                && ( $cert->{key_id} || '' ) !~ /\Q$keyIdFilter\E/i )
            {
                next;
            }

            my $v = $self->_certView( $session, $cert, $now );

            # Apply status filter
            if ( $statusFilter && $v->{status} ne $statusFilter ) {
                next;
            }

            # Apply activity filter
            if ($actKind) {
                my $last = $v->{last_used_at};
                if ( $actKind eq 'never' ) {
                    next if $last;
                }
                elsif ( $actKind eq 'within' ) {
                    next unless $last and $last >= $now - $actSecs;
                }
                else {
                    my $seen = $last || $v->{issued_at} || 0;
                    next unless $seen < $now - $actSecs;
                }
            }

            push @certs, { session_id => $sessionId, user => $user, %$v };
        }
    }

    # Newest first, by issue date or by last use; ties by issue date so that
    # pages stay stable.
    if ( $sort eq 'last_used' ) {
        @certs = sort {
                 ( $b->{last_used_at} || 0 ) <=> ( $a->{last_used_at} || 0 )
              or ( $b->{issued_at}    || 0 ) <=> ( $a->{issued_at}    || 0 )
        } @certs;
    }
    else {
        @certs =
          sort { ( $b->{issued_at} || 0 ) <=> ( $a->{issued_at} || 0 ) }
          @certs;
    }

    my $total = scalar @certs;

    # splice() takes its offset as a signed integer: an offset parsed as a
    # float larger than 2^63 arrives negative and either dies on an empty list
    # ("Modification of non-creatable array value") or silently returns the
    # end of a non-empty one. Past the end, every offset means an empty page
    # (#432).
    $offset = $total if $offset > $total;

    # Apply pagination
    if ( $offset > 0 || $limit < $total ) {
        @certs = splice( @certs, $offset, $limit );
    }

    return $self->p->sendJSONresponse(
        $req,
        {
            certificates => \@certs,
            total        => $total,
            limit        => $limit,
            offset       => $offset,
            sort         => $sort,
        }
    );
}

# POST /ssh/revoke - Revoke a certificate in persistent session
# Restricted by the sshCaAdminRule configuration parameter (default: deny).
# Users revoke their OWN certificates through /ssh/myrevoke, which needs no
# administration right.
sub sshCertRevoke {
    my ( $self, $req ) = @_;

    if ( my $denied = $self->_forbidNonAdmin($req) ) { return $denied }

    my ( $body, $bail ) = $self->_jsonBodyOrReject( $req, 'SSH revoke' );
    return $bail if $bail;

    my $sessionId = $body->{session_id};
    my $serial    = $body->{serial};

    unless ( $sessionId && $serial ) {
        return $self->p->sendError( $req, 'session_id and serial required',
            400 );
    }

    # A JSON array or object is true, so the presence check above lets it
    # through and Session->new dies on its id type constraint (#433). The
    # routes only ever hand out plain strings, so anything else is a client
    # error.
    if ( ref $sessionId || ref $serial ) {
        return $self->p->sendError(
            $req, 'session_id and serial must be strings', 400 );
    }

    # The reason is stored in the session, echoed in logger->info and in the
    # audit log: filter it like `label` is filtered in sshCaSign, so it
    # cannot forge log lines or smuggle terminal escapes into an operator's
    # console. Rejecting the whole [:cntrl:] class also covers \r\n\t.
    my $reason = $body->{reason};
    $reason = '' unless defined $reason && !ref $reason;
    $reason =~ s/^\s+|\s+$//g;
    if ( length($reason) > 256 || $reason =~ /[[:cntrl:]]/ ) {
        return $self->p->sendError( $req, 'Invalid reason', 400 );
    }

    # Get current admin user
    my $adminUser =
         $req->userData->{ $self->conf->{whatToTrace} }
      || $req->userData->{uid}
      || $req->user
      || 'unknown';

    # Load the persistent session
    my $moduleOptions = {
        storageModule => $self->conf->{persistentStorage}
          || $self->conf->{globalStorage},
        storageModuleOptions => $self->conf->{persistentStorageOptions}
          || $self->conf->{globalStorageOptions}
          || {},
    };

    # Load the existing persistent session. `force => 1` would both skip
    # existence checks AND create a fresh session row if the id is unknown —
    # neither is wanted: admin revocation must only mutate a real persistent
    # session that already carries _sshCerts.
    my $psession = Lemonldap::NG::Common::Session->new(
        {
            %$moduleOptions,
            id => $sessionId,
        }
    );

    unless ( $psession && !$psession->error ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Session not found' },
            code => 404
        );
    }

    # Refuse sessions that are not persistent (SSO/PAMTOKEN/DEVA/... all
    # carry a different `_session_kind`). `sshCertsList` only ever exposes
    # persistent session ids to the admin UI, so anything else here is a
    # caller mistake or a forged request.
    unless ( ( $psession->data->{_session_kind} // '' ) eq 'Persistent' ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Session not found' },
            code => 404
        );
    }

    # Get SSH certs from session. As in sshMyCertRevoke, a corrupted legacy
    # array means we cannot honestly say a serial is absent.
    unless ( defined $self->_legacyCerts( $psession->data ) ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Corrupted certificate data' },
            code => 500
        );
    }
    my $sshCerts = $self->_certsFromData( $psession->data );

    # Find and update the certificate
    my $found = 0;
    my $user  = $psession->data->{_session_uid} || '';
    my $keyId;
    my $target;

    for my $cert (@$sshCerts) {
        if ( ( $cert->{serial} // '' ) eq $serial ) {
            if ( $cert->{revoked_at} ) {
                return $self->p->sendJSONresponse(
                    $req,
                    { error => 'Certificate already revoked' },
                    code => 400
                );
            }

            # Its serial went into the KRL when it was replaced.
            if ( $cert->{superseded_at} ) {
                return $self->p->sendJSONresponse(
                    $req,
                    { error => 'Certificate already superseded' },
                    code => 400
                );
            }
            $cert->{revoked_at}    = time();
            $cert->{revoked_by}    = $adminUser;
            $cert->{revoke_reason} = $reason;
            $keyId                 = $cert->{key_id};
            $target                = $cert;
            $found                 = 1;
            last;
        }
    }

    unless ($found) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Certificate not found' },
            code => 404
        );
    }

    # Update session, one key for the revoked certificate only
    my %upd;
    $self->_drainLegacyCerts( $psession->data, \%upd );
    if ( my $k = $self->_certKey($target) ) {
        $upd{$k} = to_json($target);
    }
    $psession->update( \%upd );

    # Update the KRL file
    my $krlUpdated = $self->_updateKrl($serial);
    $self->_publishRevoke( $req, $serial );

    $self->logger->info( "SSH CA: Certificate revoked by '$adminUser': "
          . "serial=$serial, key_id=$keyId, user=$user, reason=$reason" );

    # Audit log
    $self->p->auditLog(
        $req,
        code    => 'SSH_CERT_REVOKED',
        user    => $user,
        admin   => $adminUser,
        message => "SSH certificate revoked for user '$user' by '$adminUser'",
        serial  => $serial,
        key_id  => $keyId,
        reason  => $reason,
        krl_update => $krlUpdated ? 'success' : 'failed',
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            result      => 1,
            serial      => $serial,
            key_id      => $keyId,
            user        => $user,
            revoked_at  => time(),
            revoked_by  => $adminUser,
            krl_updated => $krlUpdated ? JSON::true : JSON::false,
        }
    );
}

# HELPER: Store certificate in user's persistent session.
# If a record with the same fingerprint already exists, it is dropped and its
# serial revoked in the KRL: a given SSH key is represented by a single
# certificate record at a time (the most recent signature).
# HELPER: the per-certificate session key holding $cert.
#
# Keyed by fingerprint (see $CERT_PREFIX). Very old records may predate the
# fingerprint field; those fall back to the serial so they still migrate
# instead of being stranded in the legacy array.
sub _certKey {
    my ( $self, $cert ) = @_;

    return undef unless ref $cert eq 'HASH';

    # A superseded record shares its fingerprint with the one that replaced
    # it, so it lives under its serial.
    if ( $cert->{superseded_at} ) {
        return undef unless ( $cert->{serial} // '' ) ne '';
        return $CERT_OLD_PREFIX . $cert->{serial};
    }
    return $CERT_PREFIX . $cert->{fingerprint}
      if ( $cert->{fingerprint} // '' ) ne '';
    return $CERT_PREFIX . 'serial:' . $cert->{serial}
      if ( $cert->{serial} // '' ) ne '';
    return undef;
}

# HELPER: decode the pre-upgrade `_sshCerts` array of a session hash.
# Returns [] when the session has none (already migrated, or never had one)
# and undef when it holds something that is not a JSON array — callers that
# must not silently act on a partial view check for that.
sub _legacyCerts {
    my ( $self, $data ) = @_;

    my $raw = $data->{_sshCerts};
    return [] unless defined $raw and $raw ne '';
    my $list = eval { from_json($raw) };
    if ( $@ or ref $list ne 'ARRAY' ) {
        $self->logger->error("SSH CA: Corrupted _sshCerts: $@");
        return undef;
    }
    return $list;
}

# HELPER: every certificate record a session hash holds — per-key records
# (superseded ones included) first, then whatever a not-yet-drained
# `_sshCerts` array still carries.
sub _certsFromData {
    my ( $self, $data ) = @_;

    my ( @certs, %seen );
    for my $k ( sort keys %$data ) {
        next
          unless index( $k, $CERT_PREFIX ) == 0
          or index( $k, $CERT_OLD_PREFIX ) == 0;
        my $rec = eval { from_json( $data->{$k} // '' ) };
        if ( $@ or ref $rec ne 'HASH' ) {
            $self->logger->warn("SSH CA: Corrupted certificate record $k");
            next;
        }
        $seen{$k} = 1;
        push @certs, $rec;
    }
    for my $rec ( @{ $self->_legacyCerts($data) || [] } ) {
        next unless ref $rec eq 'HASH';
        my $k = $self->_certKey($rec);
        next if defined $k and $seen{$k};
        push @certs, $rec;
    }

    return \@certs;
}

# HELPER: the last recorded use of $cert, { at, host }, or undef.
#
# A superseded record carries the use it had when it was replaced. A current
# one reads the stamp pam-access keeps per fingerprint, which counts only
# when it names this certificate's serial: after a re-signature the stamp
# still describes the previous certificate until the new one is used.
sub _certUse {
    my ( $self, $data, $cert ) = @_;

    return undef unless ref $cert eq 'HASH';
    if ( $cert->{superseded_at} ) {
        return undef unless $cert->{last_used_at};
        return { at => $cert->{last_used_at}, host => $cert->{last_used_host} };
    }
    my $fp = $cert->{fingerprint} // '';
    return undef if $fp eq '';
    my $raw = $data->{ $CERT_USE_PREFIX . $fp } // '';
    return undef if $raw eq '';
    my $use = eval { from_json($raw) };
    return undef if $@ or ref $use ne 'HASH';
    return undef
      unless ( $use->{serial} // '' ) ne ''
      and ( $cert->{serial} // '' ) eq $use->{serial}
      and ( $use->{at} // '' ) =~ /\A[0-9]+\z/;
    return { at => $use->{at} + 0, host => $use->{host} };
}

# HELPER: the caller's persistent session hash, falling back to
# $req->userData. pam-access writes use stamps in the persistent session only,
# and other SSO sessions of the same user write history there too:
# $req->userData is the copy this SSO session took at login, and stays behind
# both.
sub _liveData {
    my ( $self, $req ) = @_;

    my $uid = $req->userData->{ $self->conf->{whatToTrace} || 'uid' };
    if ( defined $uid and $uid ne '' ) {
        my $ps = $self->p->getPersistentSession($uid);
        return $ps->data if $ps and !$ps->error;
    }
    return $req->userData;
}

# HELPER: status of a certificate record. A revocation wins: an administrator
# may revoke a superseded serial explicitly, and that is what to show.
sub _certStatus {
    my ( $self, $cert, $now ) = @_;

    return 'revoked'    if $cert->{revoked_at};
    return 'superseded' if $cert->{superseded_at};
    return 'expired' if $cert->{expires_at} && $cert->{expires_at} < $now;
    return 'active';
}

# HELPER: the public view of a certificate record, as /ssh/mycerts and
# /ssh/certs return it. $useData is the session hash holding the use stamps.
sub _certView {
    my ( $self, $useData, $cert, $now ) = @_;

    my $use = $self->_certUse( $useData, $cert );
    return {
        serial         => $cert->{serial},
        key_id         => $cert->{key_id},
        label          => $cert->{label},
        fingerprint    => $cert->{fingerprint},
        principals     => $cert->{principals},
        issued_at      => $cert->{issued_at},
        expires_at     => $cert->{expires_at},
        revoked_at     => $cert->{revoked_at},
        revoked_by     => $cert->{revoked_by},
        revoke_reason  => $cert->{revoke_reason},
        superseded_at  => $cert->{superseded_at},
        superseded_by  => $cert->{superseded_by},
        last_used_at   => $use ? $use->{at}   : undef,
        last_used_host => $use ? $use->{host} : undef,
        status         => $self->_certStatus( $cert, $now ),
    };
}

# HELPER: the serials of a session hash that belong in the KRL, as
# sshca-rebuild-krl collects them: revoked certificates, and superseded ones,
# whose serial went into the KRL when their key was re-signed.
sub _krlSerialsFromData {
    my ( $self, $data ) = @_;

    my %serials;
    for my $c ( @{ $self->_certsFromData($data) } ) {
        next unless ( $c->{serial} // '' ) ne '';
        next unless $c->{revoked_at} || $c->{superseded_at};
        $serials{ $c->{serial} } = 1;
    }
    return sort keys %serials;
}

# HELPER: schedule the migration of a session's `_sshCerts` array into the
# per-certificate keyspace. Every write path calls this, so the array drains
# on the first sign or revocation that touches the session.
sub _drainLegacyCerts {
    my ( $self, $data, $upd ) = @_;

    my $raw = $data->{_sshCerts};
    return unless defined $raw and $raw ne '';
    for my $rec ( @{ $self->_legacyCerts($data) || [] } ) {
        my $k = $self->_certKey($rec) or next;
        $upd->{$k} = to_json($rec) unless exists $upd->{$k};
    }
    $upd->{_sshCerts} = undef;
}

sub _storeCertificate {
    my ( $self, $req, %args ) = @_;

    my $certRecord = {
        serial      => $args{serial},
        key_id      => $args{key_id},
        label       => $args{label},
        fingerprint => $args{fingerprint},
        principals  => join( ',', @{ $args{principals} || [] } ),
        issued_at   => $args{issued_at},
        expires_at  => $args{expires_at},
    };

    # Reuse the decoded list from sshCaSign when it was passed in. Fall back
    # to re-reading the session so other internal callers don't have to
    # pre-parse.
    my $sshCerts =
      ref $args{existing} eq 'ARRAY'
      ? $args{existing}
      : $self->_certsFromData( $req->userData );

    # Only the keys of this SSH key are touched: this certificate's, the
    # superseded record's (its old key, and its history key), and history
    # records being trimmed. Every other key the user holds is left alone,
    # so a concurrent sign or revocation of another key cannot be lost.
    my $now = time();
    my %upd;
    $self->_drainLegacyCerts( $req->userData, \%upd );

    # Revoke the superseded serial in the KRL so the old certificate cannot be
    # used even if it is still within its validity window. Its record moves
    # to the history (issue #455) instead of being dropped.
    my $histMax = $self->_positiveIntConf( 'sshCaCertHistoryMax', 50 );
    my $live    = $self->_liveData($req);
    my @history = grep { $_->{superseded_at} } @{ $self->_certsFromData($live) };
    for my $c (@$sshCerts) {
        next if $c->{superseded_at};
        next
          unless $args{fingerprint}
          && ( $c->{fingerprint} || '' ) eq $args{fingerprint};
        unless ( $c->{revoked_at}
            || ( $c->{expires_at} && $c->{expires_at} < $now ) )
        {
            if ( $c->{serial} ) {
                my $ok = $self->_updateKrl( $c->{serial} );
                $self->_publishRevoke( $req, $c->{serial} );
                $self->logger->info(
                    "SSH CA: Replaced certificate serial=$c->{serial} "
                      . "(superseded by $args{serial}); KRL update "
                      . ( $ok ? 'ok' : 'FAILED' ) );
            }
        }
        if ( my $k = $self->_certKey($c) ) { $upd{$k} = undef }

        my $old = {
            %$c,
            superseded_at => $now,
            superseded_by => $args{serial},
        };
        if ( my $use = $self->_certUse( $live, $c ) ) {
            $old->{last_used_at}   = $use->{at};
            $old->{last_used_host} = $use->{host} if defined $use->{host};
        }
        if ( my $k = $self->_certKey($old) ) {
            $upd{$k} = to_json($old);
            push @history, $old;
        }
    }

    # Bound the history: drop what expired more than sshCaCertHistoryRetention
    # days ago, then keep the sshCaCertHistoryMax most recently superseded.
    # sshCaCertHistoryMax = 0 keeps none, which was the behaviour before.
    # Dropping a record that has not expired yet does not un-revoke it: its
    # serial stays in the KRL. Only sshca-rebuild-krl would no longer see it.
    my $retention =
      $self->_positiveIntConf( 'sshCaCertHistoryRetention', 30 ) * 86400;
    my $kept = 0;
    # Ties (several re-signatures in the same second) are broken on the
    # serial, compared as a decimal string (it may exceed a native integer),
    # so that the order is deterministic. With the local signer serials grow
    # with time and the later one wins; OpenBao serials are random, so with
    # `openbao` the tie-break is arbitrary, only stable.
    for my $h (
        sort {
                 ( $b->{superseded_at} || 0 ) <=> ( $a->{superseded_at} || 0 )
              or length( $b->{serial} // '' ) <=> length( $a->{serial} // '' )
              or ( $b->{serial} // '' ) cmp( $a->{serial} // '' )
        } @history
      )
    {
        my $k = $self->_certKey($h) or next;
        my $stale = $h->{expires_at} && $h->{expires_at} + $retention < $now;
        $upd{$k} = undef if $stale or ++$kept > $histMax;
    }

    # Last, so it wins over the `undef` a superseded record with the same
    # fingerprint just scheduled on the very same key.
    my $key = $self->_certKey($certRecord);
    unless ($key) {
        $self->logger->error(
            'SSH CA: certificate record has neither fingerprint nor serial');
        return 0;
    }
    $upd{$key} = to_json($certRecord);

    $self->p->updatePersistentSession( $req, \%upd );

    $self->logger->debug(
        "SSH CA: Stored certificate serial=$args{serial} fp=$args{fingerprint} in persistent session"
    );
    return 1;
}

# HELPER: Compute the OpenSSH SHA256 fingerprint of an SSH public key.
# The canonical OpenSSH form is `SHA256:<base64(sha256(blob))>` with
# trailing `=` padding stripped (see sshkey_fingerprint_b64 in sshkey.c).
# The blob is the raw wire-format key, which is exactly what's base64-
# encoded as the second whitespace-separated token of the pubkey line —
# sshCaSign's public-key regex has already validated that shape upstream,
# so no fork to ssh-keygen is needed here.
sub _sshKeyFingerprint {
    my ( $self, $sshPubKey ) = @_;
    return undef unless defined $sshPubKey;

    my ($blob_b64) = $sshPubKey =~ /^\s*\S+\s+(\S+)/;
    unless ( defined $blob_b64 && length $blob_b64 ) {
        $self->logger->error("SSH CA: Cannot parse SSH pubkey for fingerprint");
        return undef;
    }

    my $blob = decode_base64($blob_b64);
    unless ( length $blob ) {
        $self->logger->error("SSH CA: Empty blob decoding pubkey base64");
        return undef;
    }

    my $b64 = encode_base64( sha256($blob), '' );
    $b64 =~ s/=+\z//;    # OpenSSH strips trailing '=' padding

    return "SHA256:$b64";
}

# HELPER: Validate a certificate serial.
# Serials are plain decimal integers, produced by _getNextSerial or read from
# an OpenBao-signed certificate (_signOpenBao), and are handed verbatim to
# ssh-keygen through the KRL spec file, one directive per line. Anything else
# (in particular anything containing a newline) would let a caller inject
# arbitrary KRL spec directives — `id:`, `key:`, `hash:` — and revoke
# certificates it has no business revoking (issue #65).
# ssh-keygen accepts serials up to 2^64-1, i.e. at most 20 digits.
sub _validSerial {
    my ( $self, $serial ) = @_;
    return 0 unless defined $serial;

    # A JSON boolean stringifies to "1" and would otherwise match the pattern.
    return 0 if ref $serial;
    return $serial =~ /\A[0-9]{1,20}\z/ ? 1 : 0;
}

# HELPER: Bit length of an SSH "mpint" (RFC 4251 §5): a big-endian integer
# carrying a leading 0x00 byte whenever its top bit would otherwise be read
# as a sign bit. OpenSSH reports the significant bit count (a 2048-bit RSA
# modulus is 257 bytes on the wire, 2048 bits here).
sub _mpintBits {
    my ($mpint) = @_;
    return 0 unless defined $mpint;
    $mpint =~ s/\A\x00+//;
    return 0 unless length $mpint;
    my $first = ord( substr( $mpint, 0, 1 ) );
    my $bits  = ( length($mpint) - 1 ) * 8;
    while ($first) { $bits++; $first >>= 1; }
    return $bits;
}

# HELPER: Determine the real type and size of an SSH public key.
#
# The textual prefix of a pubkey line is just a label the client chose; it
# is NOT proof of what the key actually is. The truth is the base64 blob,
# which is the RFC 4253 wire format: a sequence of fields, each a uint32
# big-endian length followed by that many bytes. The first field is the key
# type; the rest depend on it (`ssh-rsa` => e, n ; `ssh-dss` => p, q, g, y ;
# `ssh-ed25519` => 32-byte point ; `sk-*` => point/curve then application ;
# `ecdsa-sha2-*` => curve name, point).
#
# Returns undef if the blob is malformed, if the type is one we don't know
# how to size, if the announced prefix disagrees with the blob, or if the
# key material contradicts the type name.
# Otherwise a hashref { type, family, bits, sized }, where `family` is the
# token used in sshCaAllowedKeyTypes and `sized` says whether `bits` is a
# variable modulus size (RSA/DSA) that sshCaMinKeyBits may be compared to.
sub _parseSshPubKey {
    my ( $self, $sshPubKey ) = @_;
    return undef unless defined $sshPubKey;

    my ( $prefix, $blob_b64 ) = $sshPubKey =~ /^\s*(\S+)\s+(\S+)/;
    return undef unless defined $blob_b64 && length $blob_b64;

    my $blob = decode_base64($blob_b64);
    return undef unless length $blob;

    my @fields;
    my $pos        = 0;
    my $len        = length $blob;
    my $truncated  = 0;
    while ( $pos + 4 <= $len ) {
        my $flen = unpack( 'N', substr( $blob, $pos, 4 ) );
        $pos += 4;

        # Truncated or simply not a wire-format key: stop, don't guess.
        if ( $flen > $len - $pos ) { $truncated = 1; last; }
        push @fields, substr( $blob, $pos, $flen );
        $pos += $flen;

        # No key type we handle needs more than this (DSA has 5).
        last if @fields >= 5;
    }
    return undef if $truncated || !@fields;

    # Trailing bytes after the last field: ssh-keygen reads the key type and
    # its fields and refuses the rest, so a blob that parses here but carries
    # extra data would only die later in the signing fork (#434).
    return undef unless $pos == $len;

    my $type = $fields[0];
    return undef unless length $type;

    # A blob whose embedded type contradicts the announced prefix is either
    # corrupt or an attempt to have the policy check read one type while
    # ssh-keygen reads another.
    return undef unless $type eq $prefix;

    # ecdsa-sha2-*: type, curve name, point. A curve that disagrees with the
    # type name means the reported size is not the size of the key. A point
    # of the right size can still be off its curve; _checkKeyPolicy asks
    # ssh-keygen about that (#434).
    if ( my $curve = $SSHCA_ECDSA_CURVES{$type} ) {
        my $is_sk = $type =~ /\Ask-/ ? 1 : 0;
        return undef unless @fields == ( $is_sk ? 4 : 3 );
        return undef unless $fields[1] eq $curve->[0];
        return undef
          unless length( $fields[2] ) == $curve->[1]
          && substr( $fields[2], 0, 1 ) eq "\x04";
        return undef if $is_sk && !length $fields[3];
        return {
            type   => $type,
            family => $SSHCA_FIXED_KEY_TYPES{$type}[0],
            bits   => $SSHCA_FIXED_KEY_TYPES{$type}[1],
            sized  => 0,
        };
    }

    # Fixed-size families carry an exact number of fields. ed25519 and its sk-
    # variant hold a 32-byte point; a wrong length is a malformed key, not a
    # weak one, and must be refused here rather than in ssh-keygen (#434).
    if ( my $fixed = $SSHCA_FIXED_KEY_TYPES{$type} ) {
        my $is_sk    = $type =~ /\Ask-/ ? 1 : 0;
        my $expected = $is_sk ? 3 : 2;    # sk-* add an application string
        return undef unless @fields == $expected;
        return undef unless length( $fields[1] ) == 32;
        return undef if $is_sk && !length $fields[2];
        return {
            type   => $type,
            family => $fixed->[0],
            bits   => $fixed->[1],
            sized  => 0,
        };
    }

    if ( $type eq 'ssh-rsa' ) {

        # ssh-rsa: type, e, n — the modulus is the size that matters.
        return undef unless @fields == 3;
        return {
            type   => $type,
            family => 'rsa',
            bits   => _mpintBits( $fields[2] ),
            sized  => 1,
        };
    }

    if ( $type eq 'ssh-dss' ) {

        # ssh-dss: type, p, q, g, y — p carries the key size.
        return undef unless @fields == 5;
        return {
            type   => $type,
            family => 'dss',
            bits   => _mpintBits( $fields[1] ),
            sized  => 1,
        };
    }

    return undef;
}

# HELPER: Ask OpenSSH whether a key line really parses as a public key.
#
# _parseSshPubKey checks the framing, the field count and the fixed sizes,
# but it cannot verify that an ECDSA point lies on its curve: a point of the
# right size can be off the curve, and the signing fork then dies after the
# policy said yes (#434). OpenSSH's own reader rejects it, sk-* families
# included: `ssh-keygen -l` reads their public half without the device.
#
# Returns 1 when the key is accepted OR when ssh-keygen cannot be run at all
# (an environment failure must not turn a valid key into a 400; the signing
# fork reports the real problem).
sub _sshKeygenAcceptsKey {
    my ( $self, $sshPubKey, $type ) = @_;

    my $pid = open my $pipe, '|-';
    unless ( defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork ssh-keygen: $!");
        return 1;
    }
    if ( $pid == 0 ) {
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        # exec failed: this is an environment failure, not a key ssh-keygen
        # refused. _exit skips the portal worker's END blocks and destructors
        # in this child.
        exec 'ssh-keygen', '-l', '-f', '-' or POSIX::_exit(127);
    }

    # ssh-keygen reads its input up to EOF and prints one fingerprint line,
    # which we discard: the exit status is the verdict.
    local $SIG{PIPE} = 'IGNORE';
    print $pipe $sshPubKey;
    print $pipe "\n" unless $sshPubKey =~ /\n$/;
    close $pipe;

    # A signal, or our own 127, means there is no verdict: let the signing
    # fork turn that into a 500 instead of blaming the caller's key.
    return 1 if $? & 127;
    my $exitCode = $? >> 8;
    return 1 if $exitCode == 127;

    $self->logger->info(
        "SSH CA: ssh-keygen refused a structurally invalid $type key "
          . "(exit $exitCode)") if $exitCode;
    return $exitCode == 0;
}

# HELPER: Apply the configured key policy to a user-supplied public key.
# Returns { ok => 1, info => {...} } or { ok => 0, error => 'message' }.
sub _checkKeyPolicy {
    my ( $self, $sshPubKey ) = @_;

    my $info = $self->_parseSshPubKey($sshPubKey);
    return { ok => 0, error => 'Unsupported or malformed SSH public key' }
      unless $info;

    my $allowedConf = $self->conf->{sshCaAllowedKeyTypes};
    $allowedConf = SSHCA_DEFAULT_KEY_TYPES
      unless defined $allowedConf && $allowedConf =~ /\S/;
    my %allowed =
      map { lc($_) => 1 } grep { length } split /[\s,]+/, $allowedConf;

    unless ( $allowed{ $info->{family} } ) {
        return {
            ok    => 0,
            error => "SSH key type '$info->{type}' is not allowed",
        };
    }

    # A minimum bit count is only meaningful inside a variable-size family:
    # Ed25519 is always 256 bits and is stronger than RSA-3072, so comparing
    # the two numbers would reject the best keys available. Fixed-size
    # families are governed by the type allowlist alone.
    if ( $info->{sized} ) {
        my $min = $self->conf->{sshCaMinKeyBits};
        $min = SSHCA_DEFAULT_MIN_BITS
          unless defined $min && $min =~ /\A[0-9]+\z/;
        if ( $info->{bits} < $min ) {
            return {
                ok => 0,
                error =>
                  "SSH key is too small ($info->{bits} bits, minimum $min)",
            };
        }
    }

    # Last structural check, once the type and size have passed: the key must
    # still parse as a key for OpenSSH. This is what catches an ECDSA point
    # off its curve, which no amount of field-counting detects (#434).
    unless ( $self->_sshKeygenAcceptsKey( $sshPubKey, $info->{type} ) ) {
        return { ok => 0, error => 'Unsupported or malformed SSH public key' };
    }

    return { ok => 1, info => $info };
}

# Section types this plugin can publish. OpenSSH also defines
# KRL_SECTION_EXTENSION (255), parsed since 9.4, but `ssh-keygen` never writes
# one and older hosts (bookworm ships 9.2) refuse the whole KRL, which would
# fail closed on every key. A type outside this set means the blob is not a
# KRL this plugin can serve: ssh-keygen refuses it, and a host installing it
# would then fail closed. The framing walk alone accepted type 0 with a zero
# length.
my %SSHCA_KRL_SECTION_TYPES = map { $_ => 1 } ( 1 .. 5 );
#   1 certificates, 2 explicit key, 3 SHA1 fingerprint,
#   4 signature,    5 SHA256 fingerprint

# HELPER: Check that a blob is a structurally complete OpenSSH KRL.
#
# A KRL truncated mid-write still starts with the `SSHKRL` magic, so a magic
# check alone (which is all consumers do) accepts it — and sshd then rejects
# EVERY key with "incomplete message", i.e. fails closed and locks the host
# out. So walk the framing: fixed header, then the two length-prefixed
# strings that close it, then the section list (u8 type + u32-prefixed blob).
# Any length running past the end of the blob means the file is truncated.
#
# Layout (see krl_to_blob() in OpenSSH sshkrl.c):
#   "SSHKRL\n\0"      8 bytes
#   format version    u32 (1)
#   krl_version       u64
#   generated_date    u64
#   flags             u64
#   reserved          string
#   comment           string
#   sections          (u8 type + string)*
sub _krlIsValid {
    my ( $self, $data ) = @_;

    return 0 unless defined $data;
    my $len = length $data;

    # 36 bytes of fixed header + 2 empty strings = smallest legal KRL
    return 0 if $len < 44;
    return 0 unless substr( $data, 0, 8 ) eq "SSHKRL\n\0";
    return 0 unless unpack( 'N', substr( $data, 8, 4 ) ) == 1;

    my $pos = 36;

    # reserved + comment
    for ( 1 .. 2 ) {
        return 0 if $len - $pos < 4;
        my $l = unpack( 'N', substr( $data, $pos, 4 ) );
        $pos += 4;
        return 0 if $l > $len - $pos;
        $pos += $l;
    }

    # sections
    while ( $pos < $len ) {
        return 0 if $len - $pos < 5;    # u8 type + u32 length
        my $sectionType = ord( substr( $data, $pos, 1 ) );
        return 0 unless $SSHCA_KRL_SECTION_TYPES{$sectionType};
        $pos += 1;
        my $l = unpack( 'N', substr( $data, $pos, 4 ) );
        $pos += 4;
        return 0 if $l > $len - $pos;
        $pos += $l;
    }

    return $pos == $len ? 1 : 0;
}

# HELPER: Take the node-wide KRL lock and return the locked filehandle.
# Callers hold the lock for as long as they keep the returned handle: it is
# released by close(), or implicitly when the lexical goes out of scope — on
# error paths included. There is a single lock, so exclusive (writers) and
# shared (readers) users cannot deadlock against each other.
# Returns undef when the lock cannot be taken.
sub _krlLock {
    my ( $self, $krlPath, $shared ) = @_;

    require Fcntl;
    my $lockPath = "$krlPath.lock";

    my $lockFh;
    unless ( open $lockFh, '>>', $lockPath ) {

        # Readers may legitimately lack write access to the KRL directory;
        # a read-only descriptor is enough for LOCK_SH.
        unless ( $shared and open $lockFh, '<', $lockPath ) {
            $self->logger->error(
                "SSH CA: Cannot open KRL lockfile $lockPath: $!");
            return undef;
        }
    }
    unless ( flock( $lockFh, $shared ? Fcntl::LOCK_SH() : Fcntl::LOCK_EX() ) ) {
        $self->logger->error("SSH CA: Cannot lock KRL: $!");
        close $lockFh;
        return undef;
    }
    return $lockFh;
}

# HELPER: (Re)write the KRL from an ssh-keygen spec file, atomically.
#
# `ssh-keygen -k` opens its -f target with O_TRUNC, so pointing it at the
# live KRL leaves a window where the file is empty or half-written while
# sshd and /ssh/revoked readers can see it (issue #59). Instead ssh-keygen
# writes to a temporary file in the KRL's own directory and we rename() it
# over the real one: readers always see either the whole old file or the
# whole new one.
#
# Everything runs under the exclusive KRL lock so that concurrent writers —
# portal workers handling a revocation, a broker event, and the
# sshca-rebuild-krl cron job, which all share this helper — do not lose each
# other's updates through interleaved read-modify-writes.
#
# %args:
#   spec   => path to the ssh-keygen KRL spec file (required)
#   update => merge into the existing KRL (ssh-keygen -u) instead of
#             replacing it
#
# Returns 1 on success, 0 on failure (the live KRL is then left untouched).
sub _writeKrl {
    my ( $self, $krlPath, %args ) = @_;

    my $specFile = $args{spec};
    unless ( defined $krlPath and length $krlPath and defined $specFile ) {
        $self->logger->error('SSH CA: _writeKrl called without KRL/spec path');
        return 0;
    }

    my $caPub = $self->sshPubKey;
    unless ($caPub) {
        $self->logger->error('SSH CA: No CA public key available for KRL');
        return 0;
    }

    # Ensure directory exists
    my $dir = $krlPath;
    $dir =~ s|/[^/]+$||;
    $dir = '.' unless length $dir;
    unless ( -d $dir ) {
        require File::Path;
        File::Path::make_path($dir);
    }

    my $lockFh = $self->_krlLock($krlPath);
    return 0 unless $lockFh;

    # Scratch dir for the KRL spec files. `newdir` (not `tempdir(CLEANUP
    # => 1)`) so it is removed when this sub returns — including on the
    # error paths below — instead of at worker exit.
    require File::Temp;
    my $tmpobj = File::Temp->newdir();
    my $tmpdir = "$tmpobj";

    # Write CA public key
    my $caPubFile = "$tmpdir/ca.pub";
    open my $fh, '>', $caPubFile or do {
        $self->logger->error("SSH CA: Cannot write CA public key: $!");
        return 0;
    };
    print $fh $caPub;
    close $fh;

    # Scratch KRL, in the target directory so rename() stays atomic
    my ( $tmpFh, $tmpKrl ) =
      eval { File::Temp::tempfile( '.krl.tmpXXXXXX', DIR => $dir, UNLINK => 0 ) };
    unless ( defined $tmpKrl ) {
        $self->logger->error("SSH CA: Cannot create temporary KRL in $dir: $@");
        return 0;
    }
    close $tmpFh;

    # Keep the current KRL's permissions; the KRL is public data served over
    # /ssh/revoked, and File::Temp would otherwise hand us a 0600 file.
    my $mode = ( stat $krlPath )[2];
    $mode = defined $mode ? $mode & 07777 : 0644;

    # `-u` is a read-modify-write: seed the scratch file with the current KRL
    # so ssh-keygen merges into a private copy, never into the live file.
    my $update = $args{update} && -s $krlPath;
    if ($update) {
        unless ( $self->_copyFile( $krlPath, $tmpKrl ) ) {
            unlink $tmpKrl;
            return 0;
        }

        # Refuse to merge into a KRL we cannot parse: ssh-keygen -u would
        # fail anyway, and rebuilding from this single spec would silently
        # drop every serial already revoked. Failing here is the safe side —
        # the sshca-rebuild-krl cron job repairs the file from the persistent
        # sessions, which are the source of truth.
        my $current = '';
        if ( open my $cfh, '<:raw', $tmpKrl ) {
            local $/;
            $current = <$cfh>;
            close $cfh;
        }
        unless ( $self->_krlIsValid($current) ) {
            $self->logger->error( "SSH CA: existing KRL $krlPath is corrupted; "
                  . "refusing to update it, run sshca-rebuild-krl to repair" );
            unlink $tmpKrl;
            return 0;
        }
    }

    # -k: Generate a KRL
    # -u: Update existing KRL
    # -s: CA public key
    # -f: KRL file
    my @cmd = ( 'ssh-keygen', '-k' );
    push @cmd, '-u' if $update;
    push @cmd, '-s', $caPubFile, '-f', $tmpKrl, $specFile;

    $self->logger->debug( "SSH CA: Writing KRL: " . join( ' ', @cmd ) );

    # Execute ssh-keygen
    my $output = '';
    my $pid    = open my $pipe, '-|';
    if ( !defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork for KRL update: $!");
        unlink $tmpKrl;
        return 0;
    }
    elsif ( $pid == 0 ) {
        open STDERR, '>&', \*STDOUT;

        # exec failed: do not run the portal worker's END blocks in this child.
        exec @cmd or POSIX::_exit(127);
    }
    else {
        local $/;
        $output = <$pipe>;
        close $pipe;
    }

    my $exitCode = $? >> 8;
    if ($exitCode) {
        $self->logger->error(
            "SSH CA: KRL update failed (exit $exitCode): $output");
        unlink $tmpKrl;
        return 0;
    }

    # Paranoia: never publish something we would refuse to serve
    my $newKrl = '';
    if ( open my $vfh, '<:raw', $tmpKrl ) {
        local $/;
        $newKrl = <$vfh>;
        eval { require IO::Handle; $vfh->sync };    # best effort durability
        close $vfh;
    }
    unless ( $self->_krlIsValid($newKrl) ) {
        $self->logger->error(
            'SSH CA: ssh-keygen produced an invalid KRL, keeping the old one');
        unlink $tmpKrl;
        return 0;
    }

    chmod $mode, $tmpKrl;
    unless ( rename $tmpKrl, $krlPath ) {
        $self->logger->error("SSH CA: Cannot install new KRL in $krlPath: $!");
        unlink $tmpKrl;
        return 0;
    }

    return 1;

    # $lockFh released here (and on every early return above)
}

# HELPER: byte copy, used to seed the scratch KRL for ssh-keygen -u
sub _copyFile {
    my ( $self, $from, $to ) = @_;

    open my $in, '<:raw', $from or do {
        $self->logger->error("SSH CA: Cannot read $from: $!");
        return 0;
    };
    open my $out, '>:raw', $to or do {
        $self->logger->error("SSH CA: Cannot write $to: $!");
        close $in;
        return 0;
    };
    my $buf;
    while (1) {
        my $n = read $in, $buf, 65536;
        unless ( defined $n ) {
            $self->logger->error("SSH CA: Cannot read $from: $!");
            close $in;
            close $out;
            return 0;
        }
        last unless $n;
        unless ( print $out $buf ) {
            $self->logger->error("SSH CA: Cannot write $to: $!");
            close $in;
            close $out;
            return 0;
        }
    }
    close $in;
    unless ( close $out ) {
        $self->logger->error("SSH CA: Cannot write $to: $!");
        return 0;
    }
    return 1;
}

# HELPER: make sure a parsable KRL exists, generating an empty one if needed.
# `ssh-keygen -k` with an empty spec produces a header-only KRL: the correct
# way to say "nothing is revoked" (issue #64). Returns 1 if a KRL is in place.
sub _ensureKrl {
    my ( $self, $krlPath ) = @_;

    return 0 unless defined $krlPath and length $krlPath;
    return 1 if -s $krlPath;

    require File::Temp;
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );
    my $specFile = "$tmpdir/empty_spec";
    open my $fh, '>', $specFile or do {
        $self->logger->error("SSH CA: Cannot write empty KRL spec: $!");
        return 0;
    };
    close $fh;

    my $ok = $self->_writeKrl( $krlPath, spec => $specFile, update => 0 );
    $self->logger->info("SSH CA: Generated an empty KRL in $krlPath") if $ok;
    return $ok;
}

# HELPER: Update KRL file with revoked serial.
# Serialized across workers on the same node, and made atomic, by _writeKrl:
# concurrent events (broker-driven + locally-triggered) can reach this helper
# in parallel, and ssh-keygen -u does a read-modify-write on the KRL file, so
# without the lock the last writer wins and earlier revocations get lost.
sub _updateKrl {
    my ( $self, $serial ) = @_;

    my $krlPath = $self->conf->{sshCaKrlPath}
      || '/var/lib/lemonldap-ng/ssh/revoked_keys';

    # Defence in depth (issue #65): the HTTP revocation routes only reach
    # this helper with a serial they matched against a stored certificate
    # record, but nothing structurally prevents another caller from passing
    # a crafted one straight into the ssh-keygen spec file.
    unless ( $self->_validSerial($serial) ) {
        $self->logger->error(
            'SSH CA: refusing to add a malformed serial to the KRL');
        return 0;
    }

    # Get CA public key for KRL
    my $keyRef = $self->conf->{sshCaKeyRef};
    unless ($keyRef) {
        $self->logger->error('SSH CA: No key reference configured for KRL');
        return 0;
    }

    require File::Temp;
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );

    # Create KRL spec file with serial to revoke
    my $specFile = "$tmpdir/revoke_spec";
    open my $fh, '>', $specFile or do {
        $self->logger->error("SSH CA: Cannot write revoke spec: $!");
        return 0;
    };
    print $fh "serial: $serial\n";
    close $fh;

    my $ok = $self->_writeKrl( $krlPath, spec => $specFile, update => 1 );
    $self->logger->info("SSH CA: KRL updated with revoked serial $serial")
      if $ok;
    return $ok;
}

# HELPER: Broadcast a revocation to sibling portals through the LLNG message
# broker (issue #9). Peers subscribe to the 'sshCaRevoke' action in init() and
# call _updateKrl on their own local KRL file. Requires a real broker
# (::Redis / ::MQTT / ::Pg); with the default ::NoBroker the publish stays on
# the local node.
sub _publishRevoke {
    my ( $self, $req, $serial ) = @_;
    return unless defined $serial && $serial ne '';
    eval {
        $self->p->HANDLER->publishEvent( $req,
            { action => 'sshCaRevoke', serial => $serial } );
    };
    if ($@) {
        $self->logger->warn(
            "SSH CA: publishEvent(sshCaRevoke, $serial) failed: $@");
    }
    return 1;
}

1;

__END__

=pod

=encoding utf8

=head1 NAME

Lemonldap::NG::Portal::Plugins::SSHCA - SSH Certificate Authority plugin

=head1 SYNOPSIS

Enable this plugin in LemonLDAP::NG Manager:
General Parameters > Plugins > SSH CA > Activation

=head1 DESCRIPTION

This plugin provides SSH certificate signing functionality, allowing users
to obtain short-lived SSH certificates signed by a trusted Certificate Authority.

=head1 ENDPOINTS

=head2 GET /ssh

Displays the SSH certificate signing web interface.
Requires authentication. This interface allows users to:

=over

=item * Paste their SSH public key

=item * Choose certificate validity duration

=item * Obtain a signed certificate for SSH authentication

=back

=head2 GET /ssh/ca

Returns the SSH CA public key in OpenSSH format.
No authentication required.

=head2 GET /ssh/revoked

Returns the SSH Key Revocation List (KRL) if configured.
No authentication required.

=head2 POST /ssh/sign

Signs a user's SSH public key and returns a certificate.
Requires authentication.

Request body (JSON):

    {
        "public_key": "ssh-ed25519 AAAA... user@host",
        "label": "laptop-pro",        # optional, falls back to the key comment
        "validity_days": 30           # optional, positive integer
    }

C<validity_days> must be a positive integer and is clamped to
C<sshCaCertMaxValidity>. Principals are always derived from the session; a
C<principals> field in the request is ignored.

The public key must satisfy the configured key policy (see
C<sshCaAllowedKeyTypes> and C<sshCaMinKeyBits>); the key type and size are
read from the decoded key blob, not from the textual prefix.

Response:

    {
        "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
        "serial": 1,
        "valid_until": "2025-01-01T12:00:00Z",
        "principals": ["user1"],
        "key_id": "user1@llng-1234567890-000001"
    }

With C<sshCaSigner> = C<openbao>, OpenBao chooses the serial (random 64-bit)
and C<serial> is a decimal string; the key ID then ends with a random nonce
instead of the serial (C<user1@llng-1234567890-9f86d081884c7d65>). If OpenBao
cannot be reached, is sealed or refuses to sign, the answer is 503.

=head2 GET /ssh/admin

Displays the SSH CA administration interface for searching and revoking
certificates. Restricted by C<sshCaAdminRule> (see L</CONFIGURATION>);
returns 403 when the rule is unset or does not match.

=head2 GET /ssh/certs

Lists/searches issued certificates from persistent sessions, across every
user. Restricted by C<sshCaAdminRule>; returns 403 when the rule is unset
or does not match.

Parameters:

=over

=item * user - Filter by user name (partial match)

=item * serial - Filter by certificate serial number (exact match)

=item * key_id - Filter by key ID (partial match)

=item * status - Filter by status: active, revoked, superseded, expired

=item * activity - Filter by last recorded use: C<never>, C<within:SECONDS>
(used in the last SECONDS) or C<idle:SECONDS> (neither used nor issued in the
last SECONDS). Anything else is refused with 400.

=item * sort - C<issued> (newest first, the default) or C<last_used> (most
recently used first, never used last). Anything else is refused with 400.

=item * limit - Maximum number of results (default: 100, max: 1000). Must be
a non-negative integer; anything else falls back to the default.

=item * offset - Offset for pagination (default: 0). Must be a non-negative
integer; anything else falls back to 0.

=back

=head2 POST /ssh/revoke

Revokes any user's certificate. Restricted by C<sshCaAdminRule>; returns
403 when the rule is unset or does not match. Users revoke their B<own>
certificates through C</ssh/myrevoke>, which requires no administration
right.

Request body (JSON):

    {
        "session_id": "persistent-session-id",
        "serial": "123",
        "reason": "Key compromised"     # optional, <= 256 chars, no controls
    }

=head1 CONFIGURATION

=over

=item sshCaActivation

Enable/disable the SSH CA plugin (default: 0)

=item portalDisplaySshCa

Display the SSH CA tab in the portal menu (default: 0).
When enabled, authenticated users will see an "SSH CA" tab in the portal
allowing them to sign their SSH keys through the web interface.

=item sshCaAdminRule

Rule (boolOrExpr) deciding who may use the administration endpoints
C</ssh/admin>, C</ssh/certs> and C</ssh/revoke> (default: B<empty, which
denies everyone>).

The rule is evaluated against the caller's session, like any LLNG rule:

    $uid eq 'admin'
    inGroup('ssh-admins')
    1                       # any authenticated user (NOT recommended)

There is deliberately no permissive default: these endpoints list every
user's certificates and can revoke any of them, so a portal that has not
been configured must not expose them. Leaving the parameter empty simply
disables the administration UI; the per-user endpoints (C</ssh/sign>,
C</ssh/mycerts>, C</ssh/myrevoke>) are unaffected.

Configuring C<locationRules> on the portal vhost on top of this rule is
still supported and still recommended as defence in depth.

=item sshCaKeyRef

Reference to the SSH CA key in the LLNG keys store (required). With
C<sshCaSigner> = C<openbao> only its C<keyPublic> is needed: the PEM public
key, or the OpenSSH line OpenBao serves on C</v1/E<lt>mountE<gt>/public_key>.

=item sshCaSigner

C<local> (default) signs with C<ssh-keygen -s> and the private key of
C<sshCaKeyRef>. C<openbao> sends every signature to OpenBao's SSH secrets
engine (C<POST /v1/E<lt>mountE<gt>/sign/E<lt>roleE<gt>>, AppRole
authentication), which holds the private key; the plugin then refuses to load
if the OpenBao parameters below are incomplete, never falls back to a local
key, and checks every certificate OpenBao returns (CA key, certified key,
principals, key ID, C<source-address>, extensions, validity, serial) before
handing it out.

=item sshCaOpenBaoUrl

OpenBao base URL, e.g. C<https://bao.example.com:8200> (required with
C<openbao>).

=item sshCaOpenBaoMount

Mount path of the SSH secrets engine (default: C<ssh>).

=item sshCaOpenBaoRole

SSH engine role used to sign (required with C<openbao>).

=item sshCaOpenBaoAppRoleMount

Mount path of the AppRole auth method (default: C<approle>).

=item sshCaOpenBaoRoleId

AppRole role_id (required with C<openbao>).

=item sshCaOpenBaoSecretId, sshCaOpenBaoSecretIdFile, sshCaOpenBaoSecretIdEnv

AppRole secret_id: the value itself, a file holding it (read at each login),
or the name of an environment variable holding it. Exactly one must be set.

=item sshCaOpenBaoCaFile

CA bundle used to check OpenBao's TLS certificate (default: the system
store, or C<lwpSslOpts>).

=item sshCaOpenBaoTimeout

Timeout of each OpenBao request, in seconds (default: 5). Portal workers
block on it.

=item sshCaCertMaxValidity

Maximum certificate validity in days (default: 365). A request asking for
more is clamped to this value. Certificates are requested in days; the
default when C<validity_days> is omitted is 30 days.

=item sshCaAllowedKeyTypes

Comma- or space-separated list of key families users may submit for signing
(default: C<ed25519,ecdsa,sk-ed25519,sk-ecdsa,rsa>). Recognised tokens:

=over

=item * C<ed25519> — C<ssh-ed25519>

=item * C<sk-ed25519> — C<sk-ssh-ed25519@openssh.com> (FIDO2)

=item * C<ecdsa> — C<ecdsa-sha2-nistp256/384/521>

=item * C<sk-ecdsa> — C<sk-ecdsa-sha2-nistp256@openssh.com> (FIDO2)

=item * C<rsa> — C<ssh-rsa>

=item * C<dss> — C<ssh-dss>, B<not allowed by default>: DSA is limited to
1024-bit keys and SHA-1 signatures, and has been disabled then removed in
recent OpenSSH releases.

=back

The family is determined by decoding the key blob, so a key cannot slip
through by mislabelling its textual prefix.

=item sshCaMinKeyBits

Minimum key size in bits (default: 2048). Only applies to families whose
size varies, i.e. RSA and DSA: an Ed25519 key is always 256 bits and is
stronger than RSA-3072, so comparing the two counts would be meaningless.
Fixed-size families are governed by C<sshCaAllowedKeyTypes> alone.

=item sshCaCertHistoryMax

Superseded certificates kept per user (default: 50). Re-signing a key keeps
the old record, marked C<superseded>, for the administration page and for
C<sshca-rebuild-krl>; the most recently superseded are kept. 0 keeps none.

=item sshCaCertHistoryRetention

Days a superseded certificate is kept after it expires (default: 30).

=item sshCaPrincipalSources

Expression to derive principals from session, separated by spaces or commas,
e.g., '$uid' or '$uid,$mail' (default: '$uid')

=item sshCaKrlPath

Path to the Key Revocation List file (optional)

=back

=head1 SEE ALSO

L<Lemonldap::NG::Portal::Plugins::PamAccess> for PAM authentication/authorization

=head1 AUTHORS

=over

=item Xavier Guimard L<yadd@debian.org>

=back

=head1 LICENSE AND COPYRIGHT

See COPYING file for details.

=cut
