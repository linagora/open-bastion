# SSH Certificate Authority plugin for LemonLDAP::NG
#
# This plugin provides SSH certificate signing functionality:
# - /ssh/ca : Public CA key endpoint (no auth required)
# - /ssh/revoked : Key Revocation List (KRL) endpoint (no auth required)
# - /ssh/sign : Sign user's SSH public key (auth required)
# - /ssh/certs : List/search issued certificates (auth required, admin only)
# - /ssh/revoke : Revoke a certificate (auth required, admin only)
#
# Requires configuration of SSH CA key in LLNG keys store.

package Lemonldap::NG::Portal::Plugins::SSHCA;

use strict;
use Mouse;
use JSON qw(from_json to_json);
use Lemonldap::NG::Common::Apache::Session;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

our $VERSION = '2.22.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'SSHCA';

# MenuTab configuration - rule for displaying the tab
has rule => (
    is      => 'ro',
    lazy    => 1,
    builder => sub { $_[0]->conf->{portalDisplaySshCa} // 0 },
);
with 'Lemonldap::NG::Portal::MenuTab';

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Check that SSH CA is enabled
    unless ( $self->conf->{sshCaActivation} ) {
        $self->logger->debug('SSH CA plugin not enabled');
        return 1;
    }

    $self->logger->debug('SSH CA plugin initialized');

    # GET /ssh/ca - Public CA key (no auth required)
    $self->addUnauthRoute(
        ssh => { ca => 'sshCaPublicKey' },
        ['GET']
    );

    # GET /ssh/revoked - Key Revocation List (no auth required)
    $self->addUnauthRoute(
        ssh => { revoked => 'sshCaKrl' },
        ['GET']
    );

    # POST /ssh/sign - Sign user's SSH key (auth required)
    $self->addAuthRoute(
        ssh => { sign => 'sshCaSign' },
        ['POST']
    );

    # GET /ssh/admin - Display the revocation interface (auth required, admin)
    $self->addAuthRoute(
        ssh => { admin => 'sshAdminInterface' },
        ['GET']
    );

    # GET /ssh/certs - List/search certificates (auth required, admin)
    $self->addAuthRoute(
        ssh => { certs => 'sshCertsList' },
        ['GET']
    );

    # POST /ssh/revoke - Revoke a certificate (auth required, admin)
    $self->addAuthRoute(
        ssh => { revoke => 'sshCertRevoke' },
        ['POST']
    );

    # GET /ssh/* - Display the signing interface (auth required, wildcard route)
    $self->addAuthRoute( ssh => { '*' => 'sshInterface' }, ['GET'] );

    return 1;
}

# MENUTAB - Display method for the portal menu tab

sub display {
    my ( $self, $req ) = @_;

    # Max validity in days (default 365 days = 1 year)
    my $maxValidityDays = $self->conf->{sshCaCertMaxValidity} || 365;

    return {
        logo => 'certificate',
        name => 'SSHCA',
        id   => 'sshca',
        html => $self->loadTemplate(
            $req, 'sshca',
            params => {
                MAX_VALIDITY_DAYS => $maxValidityDays,
                js => "$self->{p}->{staticPrefix}/common/js/sshca.js",
            }
        ),
    };
}

# GET /ssh - Display the signing interface
sub sshInterface {
    my ( $self, $req ) = @_;

    return $self->p->do( $req, [ sub { PE_OK } ] );
}

# =============================================================================
# ROUTE HANDLERS
# =============================================================================

# GET /ssh/ca.pub - Return SSH CA public key
sub sshCaPublicKey {
    my ( $self, $req ) = @_;

    # Get the key reference from config
    my $keyRef = $self->conf->{sshCaKeyRef};
    unless ($keyRef) {
        $self->logger->error(
            'SSH CA: No key reference configured (sshCaKeyRef)');
        return $self->p->sendError( $req, 'SSH CA not configured', 500 );
    }

    # Get the key from LLNG keys store
    my $keys    = $self->conf->{keys} || {};
    my $keyData = $keys->{$keyRef};
    unless ($keyData) {
        $self->logger->error("SSH CA: Key '$keyRef' not found in keys store");
        return $self->p->sendError( $req, 'SSH CA key not found', 500 );
    }

    # Get the public key
    my $publicKey = $keyData->{keyPublic};
    unless ($publicKey) {
        $self->logger->error("SSH CA: No public key for '$keyRef'");
        return $self->p->sendError( $req, 'SSH CA public key not found', 500 );
    }

    # Convert PEM public key to SSH format
    my $sshPubKey = $self->_pemToSshPublicKey( $publicKey, $keyRef );
    unless ($sshPubKey) {
        $self->logger->error(
            'SSH CA: Failed to convert public key to SSH format');
        return $self->p->sendError( $req, 'Failed to convert key', 500 );
    }

    $self->logger->debug('SSH CA: Serving public key');

    return [
        200,
        [
            'Content-Type'  => 'text/plain; charset=utf-8',
            'Cache-Control' => 'public, max-age=3600',
        ],
        [$sshPubKey]
    ];
}

# GET /ssh/revoked - Return SSH Key Revocation List (KRL)
sub sshCaKrl {
    my ( $self, $req ) = @_;

    my $krlPath = $self->conf->{sshCaKrlPath};
    unless ($krlPath) {
        $self->logger->error('SSH CA: No KRL path configured');
        return $self->p->sendError( $req, 'KRL not configured', 500 );
    }

    # Read KRL file if it exists
    if ( -f $krlPath ) {
        open my $fh, '<:raw', $krlPath or do {
            $self->logger->error("SSH CA: Cannot read KRL file: $!");
            return $self->p->sendError( $req, 'Cannot read KRL', 500 );
        };
        local $/;
        my $krlData = <$fh>;
        close $fh;

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
    else {
        # Return empty KRL if file doesn't exist
        $self->logger->debug(
            'SSH CA: KRL file not found, returning empty response');
        return [
            200,
            [
                'Content-Type'  => 'application/octet-stream',
                'Cache-Control' => 'public, max-age=300',
            ],
            ['']
        ];
    }
}

# POST /ssh/sign - Sign user's SSH public key
sub sshCaSign {
    my ( $self, $req ) = @_;

    # Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("SSH CA sign: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $userPubKey = $body->{public_key};
    unless ($userPubKey) {
        return $self->_badRequest( $req, 'public_key parameter required' );
    }

   # Validate SSH public key format: type, base64, optional comment, single line
   # Strict validation to prevent injection attacks
    unless ( $userPubKey =~
        /\A(ssh-\w+|ecdsa-sha2-\w+)\s+[A-Za-z0-9+\/]+={0,2}(?:\s+[^\r\n]*)?\z/ )
    {
        return $self->_badRequest( $req, 'Invalid SSH public key format' );
    }

    # Get validity from request (in days) or default to 30 days
    my $validityDays = $body->{validity_days} || 30;

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

        $principal .= $val;
        $pos = $match_end;
    }

    # Append remaining text after last match
    $principal .= substr( $template, $pos ) if $pos < length($template);
    $principal =~ s/^\s+|\s+$//g;    # trim

    # Split on whitespace if multiple principals
    @principals = grep { $_ ne '' } split /\s+/, $principal;

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
        return $self->_badRequest( $req, 'No principals available' );
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

    # Generate serial number
    my $serial = $self->_getNextSerial();

    # Generate key_id
    my $timestamp = time();
    my $keyId     = sprintf( "%s\@llng-%d-%06d", $user, $timestamp, $serial );

    # Sign the certificate
    my $result =
      $self->_signSshKey( $userPubKey, \@principals, $validityMinutes, $serial,
        $keyId );

    unless ( $result && $result->{certificate} ) {
        $self->logger->error('SSH CA sign: Failed to sign key');
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

    # Store certificate in persistent session for revocation tracking
    $self->_storeCertificate(
        $req,
        serial     => $serial,
        key_id     => $keyId,
        user       => $user,
        principals => \@principals,
        issued_at  => $timestamp,
        expires_at => $validUntil,
    );

    # Audit log
    $self->p->auditLog(
        $req,
        code       => 'SSH_CERT_ISSUED',
        user       => $user,
        message    => "SSH certificate issued for user '$user'",
        principals => \@principals,
        serial     => $serial,
        key_id     => $keyId,
        validity   => $validityMinutes,
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            certificate => $result->{certificate},
            serial      => $serial,
            valid_until => $validUntilISO,
            principals  => \@principals,
            key_id      => $keyId,
        }
    );
}

# =============================================================================
# HELPER METHODS
# =============================================================================

sub _badRequest {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Bad Request';

    return $self->p->sendJSONresponse( $req, { error => $message },
        code => 400 );
}

# HELPER: Get next serial number (atomic increment)
sub _getNextSerial {
    my ($self) = @_;

    my $serialPath = $self->conf->{sshCaSerialPath}
      || '/var/lib/lemonldap-ng/ssh/serial';

    # Ensure directory exists
    my $dir = $serialPath;
    $dir =~ s|/[^/]+$||;
    unless ( -d $dir ) {
        require File::Path;
        File::Path::make_path($dir);
    }

    # Read current serial, increment, and write back atomically using flock
    use Fcntl qw(:flock);

    my $serial = 1;

  # Open file in append+read mode to ensure file is created if it doesn't exist.
  # We then seek to beginning to read/write. This avoids a TOCTOU race when
  # checking existence separately from opening.
    if ( open my $fh, '+>>', $serialPath ) {

        # Acquire exclusive lock to prevent race conditions
        flock( $fh, LOCK_EX ) or do {
            $self->logger->warn("SSH CA: Cannot lock serial file: $!");
            close $fh;
            return $serial;
        };

        # Seek to beginning to read current value
        seek( $fh, 0, 0 );
        my $current = <$fh>;
        if ( defined $current ) {
            chomp $current;
            $serial = int($current) + 1 if $current =~ /^\d+$/;
        }

        # Truncate and write new serial
        seek( $fh, 0, 0 );
        truncate( $fh, 0 );
        print $fh "$serial\n";

        # Lock is released when file handle is closed
        close $fh;
    }
    else {
        $self->logger->warn("SSH CA: Cannot open serial file: $!");
    }

    return $serial;
}

# HELPER: Sign SSH key using ssh-keygen
sub _signSshKey {
    my ( $self, $userPubKey, $principals, $validityMinutes, $serial, $keyId ) =
      @_;

    require File::Temp;

    # Get CA private key
    my $keyRef = $self->conf->{sshCaKeyRef};
    unless ($keyRef) {
        $self->logger->error('SSH CA: No key reference configured');
        return undef;
    }

    my $keys    = $self->conf->{keys} || {};
    my $keyData = $keys->{$keyRef};
    unless ( $keyData && $keyData->{keyPrivate} ) {
        $self->logger->error(
            "SSH CA: Key '$keyRef' not found or has no private key");
        return undef;
    }

    # Create temp directory for key files
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );

    # Write CA private key to temp file (convert PEM to OpenSSH format)
    my $caKeyFile    = "$tmpdir/ca_key";
    my $caKeyOpenSSH = $self->_pemToOpenSSHPrivateKey( $keyData->{keyPrivate} );
    unless ($caKeyOpenSSH) {
        $self->logger->error('SSH CA: Failed to convert CA key');
        return undef;
    }

    open my $fh, '>', $caKeyFile or do {
        $self->logger->error("SSH CA: Cannot write CA key: $!");
        return undef;
    };
    print $fh $caKeyOpenSSH;
    print $fh "\n" unless $caKeyOpenSSH =~ /\n$/;
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
    my @cmd = (
        'ssh-keygen',
        '-s', $caKeyFile,                   # CA key
        '-I', $keyId,                       # Key identity
        '-n', join( ',', @$principals ),    # Principals
        '-V', "+${validityMinutes}m",       # Validity
        '-z', $serial,                      # Serial number
        $userKeyFile                        # User's public key to sign
    );

    $self->logger->debug( "SSH CA: Running: " . join( ' ', @cmd ) );

    # Execute ssh-keygen
    my $output = '';
    my $pid    = open my $pipe, '-|';
    if ( !defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork: $!");
        return undef;
    }
    elsif ( $pid == 0 ) {

        # Child process
        open STDERR, '>&', \*STDOUT;
        exec @cmd;
        exit 1;
    }
    else {
        # Parent process
        local $/;
        $output = <$pipe>;
        close $pipe;
    }

    my $exitCode = $? >> 8;
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

    return { certificate => $certificate };
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

            # RSA keys can use export_key_openssh
            $sshKey = $pk->export_key_openssh;
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

# =============================================================================
# ADMIN INTERFACE METHODS
# =============================================================================

# GET /ssh/admin - Display the revocation interface
# Access control is handled by locationRules on the portal vhost
sub sshAdminInterface {
    my ( $self, $req ) = @_;

    return $self->p->sendHtml( $req, 'sshcaadmin' );
}

# GET /ssh/certs - List/search certificates from persistent sessions
# Access control is handled by locationRules on the portal vhost
sub sshCertsList {
    my ( $self, $req ) = @_;

    # Get search parameters
    my $userFilter   = $req->param('user')   || '';
    my $serialFilter = $req->param('serial') || '';
    my $keyIdFilter  = $req->param('key_id') || '';
    my $statusFilter = $req->param('status') || '';   # active, revoked, expired
    my $limit        = int( $req->param('limit')  || 100 );
    my $offset       = int( $req->param('offset') || 0 );

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

    my @fields = qw( _session_kind _session_uid _sshCerts );

    # Search for all persistent sessions that have _sshCerts
    my $res =
      Lemonldap::NG::Common::Apache::Session->searchOnExpr( $moduleOptions,
        '_session_kind', 'Persistent', @fields );

    my @certs;
    my $now = time();

    for my $sessionId ( keys %{ $res || {} } ) {
        my $session = $res->{$sessionId};

        # Skip if no SSH certs
        next unless $session->{_sshCerts};

        my $user     = $session->{_session_uid} || '';
        my $sshCerts = eval { from_json( $session->{_sshCerts} ) };
        next if $@ || ref($sshCerts) ne 'ARRAY';

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

            # Determine status
            my $certStatus = 'active';
            if ( $cert->{revoked_at} ) {
                $certStatus = 'revoked';
            }
            elsif ( $cert->{expires_at} && $cert->{expires_at} < $now ) {
                $certStatus = 'expired';
            }

            # Apply status filter
            if ( $statusFilter && $certStatus ne $statusFilter ) {
                next;
            }

            push @certs,
              {
                session_id    => $sessionId,
                serial        => $cert->{serial},
                key_id        => $cert->{key_id},
                user          => $user,
                principals    => $cert->{principals},
                issued_at     => $cert->{issued_at},
                expires_at    => $cert->{expires_at},
                revoked_at    => $cert->{revoked_at},
                revoked_by    => $cert->{revoked_by},
                revoke_reason => $cert->{revoke_reason},
                status        => $certStatus,
              };
        }
    }

    # Sort by issued_at descending (newest first)
    @certs =
      sort { ( $b->{issued_at} || 0 ) <=> ( $a->{issued_at} || 0 ) } @certs;

    my $total = scalar @certs;

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
        }
    );
}

# POST /ssh/revoke - Revoke a certificate in persistent session
# Access control is handled by locationRules on the portal vhost
sub sshCertRevoke {
    my ( $self, $req ) = @_;

    # Parse request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("SSH revoke: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $sessionId = $body->{session_id};
    my $serial    = $body->{serial};
    my $reason    = $body->{reason} || '';

    unless ( $sessionId && $serial ) {
        return $self->_badRequest( $req, 'session_id and serial required' );
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

    my $psession = Lemonldap::NG::Common::Session->new( {
            %$moduleOptions,
            id    => $sessionId,
            force => 1,
        }
    );

    unless ( $psession && !$psession->error ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Session not found' },
            code => 404
        );
    }

    # Get SSH certs from session
    my $sshCerts = [];
    if ( $psession->data->{_sshCerts} ) {
        $sshCerts = eval { from_json( $psession->data->{_sshCerts} ) };
        if ($@) {
            $self->logger->error("SSH revoke: Corrupted _sshCerts: $@");
            return $self->p->sendJSONresponse(
                $req,
                { error => 'Corrupted certificate data' },
                code => 500
            );
        }
    }

    # Find and update the certificate
    my $found = 0;
    my $user  = $psession->data->{_session_uid} || '';
    my $keyId;

    for my $cert (@$sshCerts) {
        if ( $cert->{serial} eq $serial ) {
            if ( $cert->{revoked_at} ) {
                return $self->p->sendJSONresponse(
                    $req,
                    { error => 'Certificate already revoked' },
                    code => 400
                );
            }
            $cert->{revoked_at}    = time();
            $cert->{revoked_by}    = $adminUser;
            $cert->{revoke_reason} = $reason;
            $keyId                 = $cert->{key_id};
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

    # Update session
    $psession->update( { _sshCerts => to_json($sshCerts) } );

    # Update the KRL file
    my $krlUpdated = $self->_updateKrl($serial);

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

# HELPER: Store certificate in user's persistent session
sub _storeCertificate {
    my ( $self, $req, %args ) = @_;

    # Build certificate record
    my $certRecord = {
        serial     => $args{serial},
        key_id     => $args{key_id},
        principals => join( ',', @{ $args{principals} || [] } ),
        issued_at  => $args{issued_at},
        expires_at => $args{expires_at},
    };

    # Get existing certificates from persistent session
    my $sshCerts = [];
    if ( $req->sessionInfo->{_sshCerts} ) {
        $sshCerts = eval { from_json( $req->sessionInfo->{_sshCerts} ) };
        if ( $@ || ref($sshCerts) ne 'ARRAY' ) {
            $self->logger->warn("SSH CA: Corrupted _sshCerts, resetting: $@");
            $sshCerts = [];
        }
    }

    # Add new certificate
    push @$sshCerts, $certRecord;

    # Update persistent session
    $self->p->updatePersistentSession( $req,
        { _sshCerts => to_json($sshCerts) } );

    $self->logger->debug(
        "SSH CA: Stored certificate serial=$args{serial} in persistent session"
    );
    return 1;
}

# HELPER: Update KRL file with revoked serial
sub _updateKrl {
    my ( $self, $serial ) = @_;

    my $krlPath = $self->conf->{sshCaKrlPath}
      || '/var/lib/lemonldap-ng/ssh/revoked_keys';

    # Ensure directory exists
    my $dir = $krlPath;
    $dir =~ s|/[^/]+$||;
    unless ( -d $dir ) {
        require File::Path;
        File::Path::make_path($dir);
    }

    # Get CA public key for KRL
    my $keyRef = $self->conf->{sshCaKeyRef};
    unless ($keyRef) {
        $self->logger->error('SSH CA: No key reference configured for KRL');
        return 0;
    }

    my $keys    = $self->conf->{keys} || {};
    my $keyData = $keys->{$keyRef};
    unless ( $keyData && $keyData->{keyPublic} ) {
        $self->logger->error("SSH CA: Key '$keyRef' not found for KRL");
        return 0;
    }

    my $caPubKey = $self->_pemToSshPublicKey( $keyData->{keyPublic}, $keyRef );
    unless ($caPubKey) {
        $self->logger->error('SSH CA: Failed to convert CA public key for KRL');
        return 0;
    }

    require File::Temp;
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );

    # Write CA public key
    my $caPubFile = "$tmpdir/ca.pub";
    open my $fh, '>', $caPubFile or do {
        $self->logger->error("SSH CA: Cannot write CA public key: $!");
        return 0;
    };
    print $fh $caPubKey;
    close $fh;

    # Create KRL spec file with serial to revoke
    my $specFile = "$tmpdir/revoke_spec";
    open $fh, '>', $specFile or do {
        $self->logger->error("SSH CA: Cannot write revoke spec: $!");
        return 0;
    };
    print $fh "serial: $serial\n";
    close $fh;

    # Build ssh-keygen command to update KRL
    # -k: Generate a KRL
    # -u: Update existing KRL (only if file exists)
    # -s: CA public key
    # -f: KRL file
    my @cmd = ( 'ssh-keygen', '-k' );

    # Only use -u if KRL file already exists
    push @cmd, '-u' if -f $krlPath;

    push @cmd, '-s', $caPubFile, '-f', $krlPath, $specFile;

    $self->logger->debug( "SSH CA: Updating KRL: " . join( ' ', @cmd ) );

    # Execute ssh-keygen
    my $output = '';
    my $pid    = open my $pipe, '-|';
    if ( !defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork for KRL update: $!");
        return 0;
    }
    elsif ( $pid == 0 ) {
        open STDERR, '>&', \*STDOUT;
        exec @cmd;
        exit 1;
    }
    else {
        local $/;
        $output = <$pipe>;
        close $pipe;
    }

    my $exitCode = $? >> 8;
    if ( $exitCode != 0 ) {
        $self->logger->error(
            "SSH CA: KRL update failed (exit $exitCode): $output");
        return 0;
    }

    $self->logger->info("SSH CA: KRL updated with revoked serial $serial");
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
        "validity_minutes": 30,       # optional
        "principals": ["user1"]       # optional
    }

Response:

    {
        "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
        "serial": 1,
        "valid_until": "2025-01-01T12:00:00Z",
        "principals": ["user1"],
        "key_id": "user1@llng-1234567890-000001"
    }

=head2 GET /ssh/admin

Displays the SSH CA administration interface for searching and revoking
certificates. Access control is handled by locationRules on the portal vhost.

=head2 GET /ssh/certs

Lists/searches issued certificates from persistent sessions.
Access control is handled by locationRules on the portal vhost.

Parameters:

=over

=item * user - Filter by user name (partial match)

=item * serial - Filter by certificate serial number (exact match)

=item * key_id - Filter by key ID (partial match)

=item * status - Filter by status: active, revoked, expired

=item * limit - Maximum number of results (default: 100, max: 1000)

=item * offset - Offset for pagination (default: 0)

=back

=head2 POST /ssh/revoke

Revokes a certificate. Access control is handled by locationRules on the
portal vhost.

Request body (JSON):

    {
        "session_id": "persistent-session-id",
        "serial": "123",
        "reason": "Key compromised"     # optional
    }

=head1 CONFIGURATION

=over

=item sshCaActivation

Enable/disable the SSH CA plugin (default: 0)

=item portalDisplaySshCa

Display the SSH CA tab in the portal menu (default: 0).
When enabled, authenticated users will see an "SSH CA" tab in the portal
allowing them to sign their SSH keys through the web interface.

=item sshCaKeyRef

Reference to the SSH CA key in the LLNG keys store (required)

=item sshCaCertDefaultValidity

Default certificate validity in minutes (default: 30)

=item sshCaCertMaxValidity

Maximum certificate validity in minutes (default: 60)

=item sshCaPrincipalSources

Expression to derive principals from session, e.g., '$uid' (default: '$uid')

=item sshCaKrlPath

Path to the Key Revocation List file (optional)

=item sshCaSerialPath

Path to store the serial number counter (default: /var/lib/lemonldap-ng/ssh/serial)

=back

=head1 SEE ALSO

L<Lemonldap::NG::Portal::Plugins::PamAccess> for PAM authentication/authorization

=head1 AUTHORS

=over

=item LemonLDAP::NG team L<https://lemonldap-ng.org/team>

=back

=head1 LICENSE AND COPYRIGHT

See COPYING file for details.

=cut
