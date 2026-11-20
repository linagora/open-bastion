use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use MIME::Base64 qw(decode_base64);
use Encode       ();

BEGIN {
    require 't/test-lib.pm';
    use FindBin;
    require "$FindBin::Bin/openbao-lib.pm";
}

# Issue #476: sshCaSigner = openbao sends signing to OpenBao's SSH secrets
# engine (AppRole auth), which holds the CA private key. The CA public key
# stays pinned in the LLNG configuration, OpenBao picks the serial, and every
# certificate it returns is parsed and checked against the request before it
# is handed out. The mock (openbao-lib.pm) really signs with ssh-keygen.

system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
openbao_lib::deps_ok()
  or plan skip_all => "LWP::Protocol::PSGI / Plack::Request required";
openbao_lib::setup()
  or plan skip_all => "ssh-keygen key generation failed";

my $debug = 'error';

# Capturing logger, for the messages init() and the signer log.
{

    package t::CaptureLogger;
    our @LOGS;
    sub new { return bless {}, $_[0] }

    foreach my $level (qw(error warn notice info debug)) {
        no strict 'refs';
        *{$level} = sub { push @LOGS, "$level|$_[1]"; return 1 };
    }
    $INC{'t/CaptureLogger.pm'} = __FILE__;
}

# --- user keys ---------------------------------------------------------------
my $kdir = tempdir( CLEANUP => 1 );
my %pub;
for (
    [ ed0   => qw(-t ed25519) ],
    [ ed1   => qw(-t ed25519) ],
    [ ed2   => qw(-t ed25519) ],
    [ ed3   => qw(-t ed25519) ],
    [ rsa   => qw(-t rsa -b 3072) ],
    [ ecdsa => qw(-t ecdsa -b 384) ],
  )
{
    my ( $name, @args ) = @$_;
    system(
        'ssh-keygen', '-q',         @args, '-N', '',
        '-C',         "user-$name", '-f',  "$kdir/$name"
      ) == 0
      or plan skip_all => "ssh-keygen key generation failed";
    open my $fh, '<', "$kdir/$name.pub" or die;
    chomp( $pub{$name} = <$fh> );
    close $fh;
}

my $secretFile = "$kdir/secret_id";

sub writeSecret {
    open my $fh, '>', $secretFile or die;
    print $fh "$_[0]\n";
    close $fh;
}
writeSecret('s3cret-id');

my $krlPath = tempdir( CLEANUP => 1 ) . '/krl';

my %baseIni = (
    logLevel       => $debug,
    domain         => 'example.com',
    portal         => 'http://auth.example.com/',
    authentication => 'Demo',
    userDB         => 'Same',
    customPlugins  => '::Plugins::SSHCA',
    sshCaKeyRef    => 'sshca',

    # OpenSSH format, as served by OpenBao's /public_key: no private key.
    keys         => { sshca => { keyPublic => openbao_lib::ca_pub('main') } },
    sshCaKrlPath => $krlPath,
    sshCaCertMaxValidity     => 30,
    sshCaPrincipalSources    => '$uid',
    sshCaSignMaxPerHour      => 0,
    sshCaMaxCertsPerUser     => 0,
    sshCaSigner              => 'openbao',
    sshCaOpenBaoUrl          => $openbao_lib::URL . '/',
    sshCaOpenBaoRole         => 'llng-portal',
    sshCaOpenBaoRoleId       => 'portal-role',
    sshCaOpenBaoSecretIdFile => $secretFile,
);

my $portal = LLNG::Manager::Test->new( { ini => {%baseIni} } );
my $sshca =
  $portal->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'};

# ============================================================================
# init
# ============================================================================
ok( $sshca, 'plugin loaded in openbao mode without a private key' );
is( $sshca->signer, 'openbao', '  -> signer is openbao' );
ok( !$sshca->sshPrivKey, '  -> no local private key' );
ok( $sshca->canSign,     '  -> canSign' );
is( $sshca->baoConf->{url},     $openbao_lib::URL, '  -> trailing / stripped' );
is( $sshca->baoConf->{mount},   'ssh',             '  -> default mount' );
is( $sshca->baoConf->{timeout}, 5,                 '  -> default timeout' );
is_deeply(
    [ openbao_lib::paths() ],
    ['GET /v1/ssh/public_key'],
    '  -> the CA public key was fetched at init, without authentication'
);
ok( !defined( ( openbao_lib::requests() )[0]{token} ), '  -> no token sent' );
like(
    $portal->_get('/ssh/ca')->[2]->[0],
    qr/\Assh-ed25519 \S+ bao-main-ca\n\z/,
    '/ssh/ca serves the pinned key'
);

my $id = $portal->login('dwho');

sub sign {
    my ( $key, $label, %extra ) = @_;
    my $raw = to_json(
        { public_key => $key, label => $label, validity_days => 1, %extra } );
    return $portal->_post(
        '/ssh/sign',
        IO::String->new($raw),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($raw),
    );
}

sub mycerts {
    return expectJSON(
        $portal->_get(
            '/ssh/mycerts',
            cookie => "lemonldap=$id",
            accept => 'application/json',
        )
    )->{certificates};
}

sub certLine {
    my ($cert) = @_;
    my $f = "$kdir/c-" . int( rand 1e9 ) . '-cert.pub';
    open my $fh, '>', $f or die;
    print $fh "$cert\n";
    close $fh;
    return $f;
}

sub inspect {
    my $f = certLine( $_[0] );
    return scalar `ssh-keygen -L -f $f 2>&1`;
}

# ============================================================================
# Nominal /ssh/sign
# ============================================================================
openbao_lib::clear_requests();
my $res = sign( $pub{ed0}, 'laptop' );
is( $res->[0], 200, '/ssh/sign through OpenBao -> 200' );
my $c0 = from_json( $res->[2]->[0] );

my @req = openbao_lib::requests();
is_deeply(
    [ openbao_lib::paths() ],
    [ 'POST /v1/auth/approle/login', 'POST /v1/ssh/sign/llng-portal' ],
    '  -> AppRole login, then sign'
);
is_deeply(
    $req[0]{body},
    { role_id => 'portal-role', secret_id => 's3cret-id' },
    '  -> login with the role_id and the secret_id read from the file'
);
ok(
    $req[1]{token} && $req[1]{token} =~ /^hvs\./,
    '  -> sign carries the AppRole token'
);
my $sb = $req[1]{body};
my ($pubNoComment) = $pub{ed0} =~ /\A(\S+ \S+)/;
is( $sb->{public_key},       $pubNoComment, '  -> public_key, no comment' );
is( $sb->{valid_principals}, 'dwho',        '  -> valid_principals' );
is( $sb->{cert_type},        'user',        '  -> cert_type user' );
is( $sb->{ttl},              '1440m',       '  -> ttl in minutes' );
is( $sb->{key_id},           $c0->{key_id}, '  -> key_id as returned' );
ok( !exists $sb->{critical_options}, '  -> no critical option' );
like(
    $c0->{key_id},
    qr/\Adwho\@llng-\d+-[0-9a-f]{16}\z/,
    '  -> key_id carries a nonce, not the serial'
);

my $signed = $openbao_lib::S{signed}[-1];
is( $c0->{serial}, $signed->{serial},
    '  -> the serial is the one OpenBao chose, in decimal' );
ok( !ref $c0->{serial} && $c0->{serial} =~ /\A[1-9][0-9]*\z/,
    '  -> as a decimal string' );
is( $c0->{certificate} =~ tr/ //, 1, '  -> certificate is "<type> <b64>"' );

{
    my $L = inspect( $c0->{certificate} );
    like( $L, qr/Serial: \Q$c0->{serial}\E\n/, '  -> cert carries it' );
    like( $L, qr/Principals:\s*\n\s+dwho\n/,   '  -> principal dwho' );
    like( $L, qr/Key ID: "\Q$c0->{key_id}\E"/, '  -> key id' );
    like( $L, qr/permit-pty/, '  -> extensions from the role' );
}

{
    my ($rec) = grep { $_->{label} eq 'laptop' } @{ mycerts() };
    is( $rec && $rec->{serial},
        $c0->{serial}, '  -> the OpenBao serial is recorded in the session' );
}

# The token is cached per worker
openbao_lib::clear_requests();
is( sign( $pub{ed1}, 'desktop' )->[0], 200, 'second signature -> 200' );
is_deeply(
    [ openbao_lib::paths() ],
    ['POST /v1/ssh/sign/llng-portal'],
    '  -> no new login, the token is reused'
);

# ============================================================================
# Non-ASCII key ID and principals: sent as UTF-8, compared as UTF-8
# ============================================================================
{
    # "José" (é is in the Latin-1 range) and "Michał" (ł is above U+00FF),
    # as character strings, which is what most backends put in the session.
    #
    # whatToTrace (the key ID's user) is only set to the non-ASCII attribute
    # for José: LLNG core itself (getPSessionID's md5_hex) dies on a
    # whatToTrace above U+00FF, before and independently of this plugin.
    # Michał's key ID goes through _signSshKey directly below.
    my $conf = $portal->p->conf;
    local $conf->{sshCaPrincipalSources} = '$cn';
    my $i = 0;
    for my $name ( "Jos\x{e9}", "Micha\x{142}" ) {
        local $conf->{whatToTrace} = $name =~ /[^\x00-\xff]/ ? 'uid' : 'cn';
        my $user = $conf->{whatToTrace} eq 'cn' ? $name : 'dwho';
        $portal->p->getApacheSession( $id, kind => 'SSO' )
          ->update( { cn => $name } );
        openbao_lib::clear_requests();
        my $label = 'utf8-' . $i++;
        $res = eval { sign( $pub{ed3}, $label ) };
        is( $res && $res->[0], 200, "user $label (non-ASCII) signed -> 200" )
          or diag $@;
        my ($req) = grep { $_->{path} =~ m{/sign/} } openbao_lib::requests();
        my $sent =
          eval { Encode::decode( 'UTF-8', $req->{raw}, Encode::FB_CROAK ) };
        ok( defined $sent, '  -> the body sent is valid UTF-8' );
        my $json = defined $sent ? from_json($sent) : {};
        is( $json->{valid_principals}, $name, '  -> with the principal' );
        like(
            $json->{key_id} // '',
            qr/\A\Q$user\E\@llng-\d+-[0-9a-f]{16}\z/,
            '  -> and the key ID'
        );

        # The PSGI body is UTF-8 bytes.
        my $c =
          $res && $res->[0] == 200
          ? JSON::decode_json( $res->[2]->[0] )
          : {};
        my $p =
          $c->{certificate}
          ? $sshca->_parseSshCert(
            decode_base64( ( split / /, $c->{certificate} )[1] ) )
          : {};
        is_deeply(
            $p->{principals},
            [ Encode::encode_utf8($name) ],
            '  -> the certificate carries the UTF-8 principal'
        );
        is(
            $p->{key_id},
            Encode::encode_utf8( $c->{key_id} // '' ),
            '  -> and the UTF-8 key ID'
        );
    }
    $portal->p->getApacheSession( $id, kind => 'SSO' )
      ->update( { cn => 'Doctor who' } );
}

# _toChars: characters and ASCII unchanged, UTF-8 bytes decoded, other
# bytes read as Latin-1.
{
    my $t = \&Lemonldap::NG::Portal::Plugins::SSHCA::_toChars;
    is( $t->('dwho'),          'dwho',         '_toChars: ASCII' );
    is( $t->("Micha\x{142}"),  "Micha\x{142}", '_toChars: characters' );
    is( $t->("Jos\xc3\xa9"),   "Jos\x{e9}",    '_toChars: UTF-8 bytes' );
    is( $t->("Jos\xe9"),       "Jos\x{e9}",    '_toChars: Latin-1 bytes' );
    is( $t->("Micha\xc5\x82"), "Micha\x{142}", '_toChars: UTF-8 bytes > FF' );
}

# Key ID above U+00FF, and a session holding UTF-8 bytes rather than
# characters: the same certificate.
for my $v ( "Micha\x{142}", "Micha\xc5\x82" ) {
    my $kind = utf8::is_utf8($v) ? 'characters' : 'UTF-8 bytes';
    my $r =
      eval { $sshca->_signSshKey( $pub{ed3}, [$v], 5, undef, "$v\@llng-1-00" ) };
    ok( $r && $r->{certificate}, "$kind principal and key ID signed" )
      or diag $@;
    my $body = ( openbao_lib::requests() )[-1]{body};
    is( $body->{valid_principals}, "Micha\x{142}",  '  -> sent decoded once' );
    is( $body->{key_id}, "Micha\x{142}\@llng-1-00", '  -> key ID too' );
    my $p = $r
      && $sshca->_parseSshCert(
        decode_base64( ( split / /, $r->{certificate} )[1] ) );
    is( $p && $p->{key_id},
        "Micha\xc5\x82\@llng-1-00",
        '  -> the certificate carries it in UTF-8' );
}

# ============================================================================
# Redirects are not followed: the token and the secret_id stay home
# ============================================================================
openbao_lib::route_host('evil.test');
{
    local $openbao_lib::S{redirect_login} =
      'http://evil.test/v1/auth/approle/login';
    local $openbao_lib::S{foreign} = [];
    $sshca->_baoToken(undef);
    is( sign( $pub{ed3}, 'redir' )->[0], 503, 'login redirected -> 503' );
    is_deeply( $openbao_lib::S{foreign},
        [], '  -> nothing reached the other host' );
}
{
    local $openbao_lib::S{redirect_sign} =
      'http://evil.test/v1/ssh/sign/llng-portal';
    local $openbao_lib::S{foreign} = [];
    $sshca->_baoToken(undef);
    openbao_lib::clear_requests();
    is( sign( $pub{ed3}, 'redir' )->[0], 503, 'sign redirected -> 503' );
    is( scalar( grep { /login/ } openbao_lib::paths() ),
        1, '  -> after a real login' );
    is_deeply( $openbao_lib::S{foreign},
        [], '  -> nothing reached the other host' );
}
is( $sshca->ua->max_size, 1024 * 1024, 'OpenBao answers capped to 1 MiB' );

# ============================================================================
# Revocation through the KRL with an OpenBao serial, above 2^63
# ============================================================================
{
    # 0xfedcba9876543210: above 2^63, so a native signed integer, or hex()
    # on a 32-bit perl, would get it wrong.
    local $openbao_lib::S{tamper} = { serial => '18364758544493064720' };
    $res = sign( $pub{ed2}, 'highserial' );
}
is( $res->[0], 200, 'certificate with a serial above 2^63 -> 200' );
my $high = from_json( $res->[2]->[0] );
is( $high->{serial}, '18364758544493064720',
    '  -> hex serial_number converted to decimal exactly' );
{
    my $raw = to_json( { serial => $high->{serial} } );
    is(
        $portal->_post(
            '/ssh/myrevoke',
            IO::String->new($raw),
            cookie => "lemonldap=$id",
            type   => 'application/json',
            length => length($raw),
        )->[0],
        200,
        '  -> revoked with /ssh/myrevoke'
    );
    my $f = certLine( $high->{certificate} );
    like(
        `ssh-keygen -Q -f $krlPath $f 2>&1`,
        qr/REVOKED/,
        '  -> the KRL revokes the OpenBao-issued certificate'
    );
    $f = certLine( $c0->{certificate} );
    like(
        `ssh-keygen -Q -f $krlPath $f 2>&1`,
        qr/: ok/,
        '  -> and not another one'
    );
}

# Other key types: the certificate layout depends on the key type.
for my $k (qw(rsa ecdsa)) {
    is( sign( $pub{$k}, "key-$k" )->[0], 200, "$k key signed through OpenBao" );
}

# ============================================================================
# Token lifecycle
# ============================================================================

# Less than 30s left: log in again before signing.
$sshca->_baoTokenExp( time + 10 );
openbao_lib::clear_requests();
is( sign( $pub{ed0}, 'laptop' )->[0], 200, 'token about to expire -> 200' );
is_deeply(
    [ openbao_lib::paths() ],
    [ 'POST /v1/auth/approle/login', 'POST /v1/ssh/sign/llng-portal' ],
    '  -> logged in again first'
);

# Token revoked on the OpenBao side: 403, login again once, retry once.
$openbao_lib::S{tokens} = {};
openbao_lib::clear_requests();
is( sign( $pub{ed0}, 'laptop' )->[0], 200, 'token revoked by OpenBao -> 200' );
is_deeply(
    [ openbao_lib::paths() ],
    [
        'POST /v1/ssh/sign/llng-portal',
        'POST /v1/auth/approle/login',
        'POST /v1/ssh/sign/llng-portal'
    ],
    '  -> 403, login, retry'
);

# A 403 that persists: only one retry, then 503.
{
    local $openbao_lib::S{fail_sign} =
      [ 403, { errors => ['permission denied'] } ];
    openbao_lib::clear_requests();
    is( sign( $pub{ed0}, 'laptop' )->[0], 503, 'persistent 403 -> 503' );
    is( scalar( grep { /sign/ } openbao_lib::paths() ),
        2, '  -> signed twice, not more' );
}

# A lease_duration that is not a number gives no lease: re-login every time.
for my $lease ( 'abc', -1, 1.5, 0 ) {
    local $openbao_lib::S{lease} = $lease;
    $sshca->_baoToken(undef);
    openbao_lib::clear_requests();
    is( sign( $pub{ed0}, 'laptop' )->[0], 200, "lease_duration $lease -> 200" );
    is( sign( $pub{ed0}, 'laptop' )->[0], 200, '  -> twice' );
    is( scalar( grep { /login/ } openbao_lib::paths() ),
        2, '  -> no lease: logged in for each signature' );
}
$sshca->_baoToken(undef);

# The secret_id file is read at each login: a rotated secret is picked up.
{
    local $openbao_lib::S{secret_id} = 'rotated';
    $sshca->_baoToken(undef);
    is( sign( $pub{ed0}, 'laptop' )->[0], 503, 'wrong secret_id -> 503' );
    writeSecret('rotated');
    is( sign( $pub{ed0}, 'laptop' )->[0],
        200, '  -> rewriting the file fixes it, no reload' );
    writeSecret('s3cret-id');
    $sshca->_baoToken(undef);
}

# ============================================================================
# OpenBao unavailable -> 503, nothing recorded
# ============================================================================
my $nbCerts = scalar @{ mycerts() };
for my $fail (
    [ 500, { errors => ['internal error'] } ],
    [ 503, { errors => ['Vault is sealed'] } ],
    [ 400, { errors => ['ttl is larger than maximum allowed'] } ],
  )
{
    local $openbao_lib::S{fail_sign} = $fail;
    $res = sign( $pub{ed3}, 'new' );
    is( $res->[0], 503, "OpenBao answers $fail->[0] -> 503" );
    is(
        from_json( $res->[2]->[0] )->{error},
        'Failed to sign SSH key',
        '  -> error message'
    );
}
{
    local $openbao_lib::S{fail_login} = [ 503, { errors => ['sealed'] } ];
    $sshca->_baoToken(undef);
    is( sign( $pub{ed3}, 'new' )->[0], 503, 'login fails -> 503' );
}
is( scalar @{ mycerts() }, $nbCerts, '  -> no certificate recorded' );

# Connection refused, then a server that never answers (timeout).
{
    my $bao = $sshca->baoConf;
    local $bao->{url} = 'http://127.0.0.1:1';
    delete $sshca->{ua};
    $sshca->_baoToken(undef);
    is( sign( $pub{ed3}, 'new' )->[0], 503, 'connection refused -> 503' );

    my $srv = IO::Socket::INET->new(
        Listen    => 5,
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Proto     => 'tcp',
    );
  SKIP: {
        skip 'cannot listen on 127.0.0.1', 2 unless $srv;
        local $bao->{url}     = 'http://127.0.0.1:' . $srv->sockport;
        local $bao->{timeout} = 1;
        delete $sshca->{ua};
        my $t0 = time;
        is( sign( $pub{ed3}, 'new' )->[0], 503, 'OpenBao times out -> 503' );
        cmp_ok( time - $t0, '<=', 5, '  -> after sshCaOpenBaoTimeout' );
    }
}
delete $sshca->{ua};
$sshca->_baoToken(undef);
is( sign( $pub{ed3}, 'new' )->[0], 200, 'back to normal' );

# ============================================================================
# Malformed answers -> 500 (sign) / 503 (login), never a crash
# ============================================================================
for my $body (
    '[]',                               '1',
    '"a"',                              'true',
    'not json',                         '{"auth":"a"}',
    '{"auth":[]}',                      '{"auth":{"client_token":[]}}',
    '{"auth":{"client_token":"a\nb"}}', '{"auth":{"client_token":""}}'
  )
{
    local $openbao_lib::S{fail_login} = [ 200, $body ];
    $sshca->_baoToken(undef);
    my $r = eval { sign( $pub{ed3}, 'new' ) };
    is( $r && $r->[0], 503, "login answers $body -> 503" );
}
$sshca->_baoToken(undef);

my ( $type0, $b640 ) = split / /, $c0->{certificate};
my $blob0 = decode_base64($b640);
for my $data (
    'a',
    [],
    {},
    { serial_number => [],  signed_key => $c0->{certificate} },
    { serial_number => 'a', signed_key => {} },
    { serial_number => 'a' },
    { signed_key    => $c0->{certificate} },
    { serial_number => 'a', signed_key => 'garbage' },
    { serial_number => 'a', signed_key => "$type0 !!!!" },
    {
        serial_number => 'a',
        signed_key    => "$type0 "
          . MIME::Base64::encode_base64( substr( $blob0, 0, 100 ), '' )
    },
    {
        serial_number => 'a',
        signed_key => "$type0 " . MIME::Base64::encode_base64( "$blob0\0", '' )
    },
    {
        serial_number => 'a',
        signed_key    => "ssh-ed25519 $b640"
    },
  )
{
    local $openbao_lib::S{tamper} = { response => $data };
    my $r = eval { sign( $pub{ed3}, 'new' ) };
    is(
        $r && $r->[0],
        500,
        'sign answers data='
          . to_json( $data, { allow_nonref => 1 } )
          . ' -> 500'
    );
}
for my $body ( '[]', '1', 'not json', '{"data":"a"}', '{"data":[]}' ) {
    local $openbao_lib::S{fail_sign} = [ 200, $body ];
    my $r = eval { sign( $pub{ed3}, 'new' ) };
    is( $r && $r->[0], 500, "sign answers $body -> 500" );
}

# ============================================================================
# A certificate other than the one requested is refused (500)
# ============================================================================
my %tampers = (
    'serial_number differs from the certificate serial' =>
      [ { serial_hex => 'deadbeef' }, qr/serial differs from serial_number/ ],
    'serial_number is not hexadecimal' =>
      [ { serial_hex => '12:34' }, qr/not a 64-bit hexadecimal/ ],
    'serial 0 (cannot be revoked by serial)' =>
      [ { serial => 0, serial_hex => '0' }, qr/serial is unusable/ ],
    'host certificate'      => [ { host => 1 }, qr/not a user certificate/ ],
    'signed by another CA'  => [ { ca => 'other' }, qr/signed by another CA/ ],
    'certifies another key' =>
      [ { key => $pub{ed0} }, qr/certifies another key/ ],
    'principals differ' =>
      [ { principals => 'dwho,root' }, qr/principals differ/ ],
    'principal missing' =>
      [ { principals => 'nobody' }, qr/principals differ/ ],
    'principal repeated' =>
      [ { principals => 'dwho,dwho' }, qr/principals differ/ ],
    'key id differs' => [ { key_id => 'something-else' }, qr/key ID differs/ ],
    'source-address not requested' =>
      [ { source => '10.0.0.1' }, qr/source-address differs/ ],
    'unexpected critical option' => [
        { options => ['force-command=/bin/sh'] },
        qr/unexpected critical options/
    ],
    'unexpected extension' =>
      [ { options => ['no-touch-required'] }, qr/unexpected extensions/ ],
    'longer than requested' =>
      [ { ttl => '+30d' }, qr/validity does not match/ ],
    'shorter than requested' =>
      [ { ttl => '+1h' }, qr/validity does not match/ ],
);
for my $name ( sort keys %tampers ) {
    my ( $tamper, $why ) = @{ $tampers{$name} };
    local $openbao_lib::S{tamper} = $tamper;
    @t::CaptureLogger::LOGS = ();
    my $log = $sshca->logger;
    $sshca->logger( t::CaptureLogger->new );
    $res = sign( $pub{ed3}, 'new' );
    $sshca->logger($log);
    is( $res->[0], 500, "$name -> 500" );
    my ($err) =
      grep { /^error\|SSH CA: refusing the certificate/ }
      @t::CaptureLogger::LOGS;
    like( $err // '', $why, '  -> refused for that reason' )
      or diag explain \@t::CaptureLogger::LOGS;
}
is( scalar @{ mycerts() }, $nbCerts + 1, 'none of them was recorded' );

# ============================================================================
# Hop certificates: source-address and a TTL in seconds (pam-access path)
# ============================================================================
{
    openbao_lib::clear_requests();
    my $r = $sshca->_signSshKey(
        $pub{ed3}, ['french'], 2, 42,
        'bastion=b;user=french;target=t',
        { validity => '+120s', source_address => '192.0.2.7' }
    );
    ok( $r && $r->{certificate}, 'hop certificate signed' );
    my $body = ( openbao_lib::requests() )[-1]{body};
    is( $body->{ttl}, '120s', '  -> ttl in seconds' );
    is_deeply(
        $body->{critical_options},
        { 'source-address' => '192.0.2.7' },
        '  -> source-address requested'
    );
    isnt( $r->{serial}, 42, '  -> the given serial is ignored' );
    is(
        $r->{serial},
        $openbao_lib::S{signed}[-1]{serial},
        '  -> the OpenBao one is returned'
    );
    my $L = inspect( $r->{certificate} );
    like( $L, qr/source-address 192\.0\.2\.7/, '  -> pinned' );

    my $cert = $sshca->_parseSshCert(
        decode_base64( ( split / /, $r->{certificate} )[1] ) );
    my $d = $cert->{valid_before} - time;
    ok( $d > 100 && $d <= 125, "  -> valid ~120s (${d}s)" );

    for my $t ( { source => '192.0.2.8' }, { source => '' } ) {
        local $openbao_lib::S{tamper} = $t;
        my $r = $sshca->_signSshKey(
            $pub{ed3}, ['french'], 2, 42,
            'bastion=b;user=french;target=t',
            { validity => '+120s', source_address => '192.0.2.7' }
        );
        ok( !( $r && $r->{certificate} ),
            "  -> refused when OpenBao sets source-address '$t->{source}'" );
        is( $r && $r->{error}, 'invalid', '  -> as invalid, not unavailable' );
    }

    # The end of validity: at most 60s late (a hop lives 120s), up to 300s
    # early (a shorter certificate grants less).
    for my $case ( [ '+190s', 0 ], [ '+300s', 0 ], [ '+60s', 1 ] ) {
        my ( $ttl, $ok ) = @$case;
        local $openbao_lib::S{tamper} = { ttl => $ttl };
        my $r = $sshca->_signSshKey(
            $pub{ed3}, ['french'], 2, 42,
            'bastion=b;user=french;target=t',
            { validity => '+120s', source_address => '192.0.2.7' }
        );
        is(
            !!( $r && $r->{certificate} ),
            !!$ok,
            "  -> 120s requested, $ttl signed: "
              . ( $ok ? 'accepted' : 'refused' )
        );
    }

    my $bad = $sshca->_signSshKey( $pub{ed3}, ['french'], 2, 42, 'k',
        { validity => '20260101' } );
    ok( !( $bad && $bad->{certificate} ),
        '  -> an absolute validity spec is refused' );
    $bad = $sshca->_signSshKey( $pub{ed3}, ['a,b'], 2, 42, 'k' );
    ok( !( $bad && $bad->{certificate} ),
        '  -> a principal with a comma is refused' );
}

# ============================================================================
# _parseSshCert on its own
# ============================================================================
{
    my $p = $sshca->_parseSshCert($blob0);
    ok( $p, 'a genuine certificate parses' );
    is( $p->{cert_type}, 1,             '  -> user certificate' );
    is( $p->{serial},    $c0->{serial}, '  -> serial in decimal' );
    is_deeply( $p->{principals}, ['dwho'], '  -> principals' );
    is(
        $p->{key_blob},
        decode_base64( ( split / /, $pub{ed0} )[1] ),
        '  -> certified key blob'
    );
    is(
        $p->{signature_key},
        decode_base64( ( split / /, openbao_lib::ca_pub('main') )[1] ),
        '  -> signature key'
    );
    is_deeply( $p->{critical_options}, {}, '  -> no critical option' );
    ok( exists $p->{extensions}{'permit-pty'}, '  -> extensions' );

    my $dies   = 0;
    my $parsed = 0;
    for my $n ( 0 .. length($blob0) - 1 ) {
        my $r = eval { $sshca->_parseSshCert( substr( $blob0, 0, $n ) ) };
        $dies++   if $@;
        $parsed++ if $r;
    }
    is( $dies,   0, 'truncated certificates never die' );
    is( $parsed, 0, '  -> and never parse' );
    ok( !$sshca->_parseSshCert("$blob0\0"), '  -> nor with a trailing byte' );

    # Flip every byte of the framing area: never die.
    $dies = 0;
    for my $i ( 0 .. length($blob0) - 1 ) {
        my $b = $blob0;
        substr( $b, $i, 1 ) = chr( ord( substr( $b, $i, 1 ) ) ^ 0xff );
        eval { $sshca->_parseSshCert($b) };
        $dies++ if $@;
    }
    is( $dies, 0, 'corrupted certificates never die' );
}

# ============================================================================
# init: incomplete or invalid configurations refuse to load
# ============================================================================
{
    my %conf  = %{ $portal->p->conf };
    my @cases = (
        [ 'unknown signer'    => { sshCaSigner     => 'vault' } ],
        [ 'no URL'            => { sshCaOpenBaoUrl => undef } ],
        [ 'ftp URL'           => { sshCaOpenBaoUrl => 'ftp://bao.test' } ],
        [ 'URL with a query'  => { sshCaOpenBaoUrl => 'http://bao.test/?a' } ],
        [ 'URL with userinfo' => { sshCaOpenBaoUrl => 'http://u:p@bao.test' } ],
        [ 'not a URL'         => { sshCaOpenBaoUrl => 'bao.test' } ],
        [ 'no role'           => { sshCaOpenBaoRole  => '' } ],
        [ 'role with a slash' => { sshCaOpenBaoRole  => 'a/b' } ],
        [ 'role with ..'      => { sshCaOpenBaoRole  => '..' } ],
        [ 'mount with ?'      => { sshCaOpenBaoMount => 'ssh?x=1' } ],
        [ 'mount with ..'     => { sshCaOpenBaoMount => 'ssh/../sys' } ],
        [
            'approle mount with %' =>
              { sshCaOpenBaoAppRoleMount => 'app%2frole' }
        ],
        [ 'no role id'   => { sshCaOpenBaoRoleId       => ' ' } ],
        [ 'no secret id' => { sshCaOpenBaoSecretIdFile => undef } ],
        [
            'two secret ids' => {
                sshCaOpenBaoSecretId     => 'x',
                sshCaOpenBaoSecretIdFile => $secretFile
            }
        ],
        [
            'unreadable CA file' =>
              { sshCaOpenBaoCaFile => "$kdir/does-not-exist" }
        ],
        [ 'no public key' => { keys => { sshca => {} } } ],
        [
            'invalid public key' => {
                keys => { sshca => { keyPublic => 'ssh-ed25519 AAAAC3Nz' } }
            }
        ],
        [
            'local mode without private key' => { sshCaSigner => 'local' }
        ],
    );
    for my $case (@cases) {
        my ( $name, $over ) = @$case;
        my $c = { %conf, %$over };
        @t::CaptureLogger::LOGS = ();
        my $obj = Lemonldap::NG::Portal::Plugins::SSHCA->new(
            { p => $portal->p, conf => $c, logger => t::CaptureLogger->new } );
        ok( !$obj->init, "init refused: $name" );
        ok( ( grep { /^error\|/ } @t::CaptureLogger::LOGS ),
            '  -> with an error logged' );
        ok( !$obj->canSign, '  -> canSign is false' )
          if $name !~ /signer|key/;
    }

    # The secret_id from the configuration or from the environment.
    for my $over (
        { sshCaOpenBaoSecretIdFile => undef, sshCaOpenBaoSecretId => 'x' },
        {
            sshCaOpenBaoSecretIdFile => undef,
            sshCaOpenBaoSecretIdEnv  => 'T_BAO_SECRET'
        },
      )
    {
        my $c   = { %conf, %$over };
        my $obj = Lemonldap::NG::Portal::Plugins::SSHCA->new(
            { p => $portal->p, conf => $c, logger => t::CaptureLogger->new } );
        my $bao = $obj->_openBaoConf;
        ok( $bao, 'secret_id source accepted: ' . join ',', sort keys %$over );
        $obj->baoConf($bao);
        local $ENV{T_BAO_SECRET} = " from-env\n";
        is(
            $obj->_baoSecretId,
            $over->{sshCaOpenBaoSecretId} // 'from-env',
            '  -> read and trimmed'
        );
    }
}

# ============================================================================
# init: OpenBao's CA key differs from the pinned one -> loud error, but the
# plugin loads (and every certificate is refused by the checks above).
# ============================================================================
SKIP: {

    # DEBUG / LLNGLOGLEVEL replace the logger given in the ini.
    skip 'the test logger is overridden by DEBUG/LLNGLOGLEVEL', 4
      if $ENV{DEBUG} || $ENV{LLNGLOGLEVEL};
    local $openbao_lib::S{public_key} = openbao_lib::ca_pub('other');
    @t::CaptureLogger::LOGS = ();
    my $p2 = LLNG::Manager::Test->new(
        { ini => { %baseIni, logger => 't::CaptureLogger' } } );
    ok(
        $p2->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'},
        'plugin still loads when OpenBao serves another CA key'
    );
    ok( (
            grep { /^error\|.*differs from keys\/sshca\/keyPublic/ }
              @t::CaptureLogger::LOGS
        ),
        '  -> the mismatch is logged as an error'
    ) or diag explain \@t::CaptureLogger::LOGS;

    @t::CaptureLogger::LOGS = ();
    local $openbao_lib::S{public_key};
    local $openbao_lib::S{fail_public_key} = [ 503, [], ['sealed'] ];
    my $p3 = LLNG::Manager::Test->new(
        { ini => { %baseIni, logger => 't::CaptureLogger' } } );
    ok( $p3->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'},
        'plugin loads when OpenBao is down at startup' );
    ok( (
            grep { /^warn\|.*could not fetch the CA public key/ }
              @t::CaptureLogger::LOGS
        ),
        '  -> with a warning'
    );
}

# ============================================================================
# The local signer is untouched
# ============================================================================
SKIP: {
    skip 'openssl not available', 6
      unless system("which openssl >/dev/null 2>&1") == 0;
    my $d = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $d/ca.key 2>/dev/null"
      ) == 0
      && system("openssl rsa -in $d/ca.key -pubout -out $d/ca.pub 2>/dev/null")
      == 0
      or skip 'openssl key generation failed', 6;
    local $/;
    open my $fh, '<', "$d/ca.key" or die;
    my $priv = <$fh>;
    open $fh, '<', "$d/ca.pub" or die;
    my $caPub = <$fh>;
    close $fh;

    my $local = LLNG::Manager::Test->new( {
            ini => {
                %baseIni,
                sshCaSigner => undef,
                keys        =>
                  { sshca => { keyPublic => $caPub, keyPrivate => $priv } },
                sshCaKrlPath => tempdir( CLEANUP => 1 ) . '/krl',
            }
        }
    );
    my $l = $local->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'};
    is( $l->signer, 'local', 'no sshCaSigner -> local' );
    ok( $l->canSign, '  -> canSign with the local key' );
    openbao_lib::clear_requests();
    my $r = $l->_signSshKey( $pub{ed0}, ['dwho'], 5, 123456, 'kid' );
    ok( $r && $r->{certificate}, '  -> signs locally' );
    is( $r && $r->{serial}, 123456, '  -> returns the serial it was given' );
    like(
        inspect( $r->{certificate} ),
        qr/Serial: 123456\n/,
        '  -> and the certificate carries it'
    );
    is( scalar( openbao_lib::requests() ), 0, '  -> without any HTTP request' );
}

clean_sessions();
done_testing();
