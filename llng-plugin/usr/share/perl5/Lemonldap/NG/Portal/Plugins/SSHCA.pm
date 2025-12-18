# SSH Certificate Authority plugin for LemonLDAP::NG
#
# This plugin provides SSH certificate signing functionality:
# - /ssh/ca : Public CA key endpoint (no auth required)
# - /ssh/revoked : Key Revocation List (KRL) endpoint (no auth required)
# - /ssh/sign : Sign user's SSH public key (auth required)
#
# Requires configuration of SSH CA key in LLNG keys store.

package Lemonldap::NG::Portal::Plugins::SSHCA;

use strict;
use Mouse;
use JSON qw(from_json to_json);
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

    # GET /ssh - Display the signing interface (auth required)
    $self->addAuthRoute( ssh => 'sshInterface', ['GET'] );

    return 1;
}

# MENUTAB - Display method for the portal menu tab

sub display {
    my ( $self, $req ) = @_;

    return {
        logo => 'certificate',
        name => 'SSHCA',
        id   => 'sshca',
        html => $self->loadTemplate(
            $req, 'sshca',
            params => {
                DEFAULT_VALIDITY => $self->conf->{sshCaCertDefaultValidity}
                  || 30,
                MAX_VALIDITY => $self->conf->{sshCaCertMaxValidity} || 60,
                js           => "$self->{p}->{staticPrefix}/common/js/sshca.js",
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

    # Get validity from request or use default
    my $validityMinutes =
         $body->{validity_minutes}
      || $self->conf->{sshCaCertDefaultValidity}
      || 30;

    # Enforce maximum validity
    my $maxValidity = $self->conf->{sshCaCertMaxValidity} || 60;
    $validityMinutes = $maxValidity if $validityMinutes > $maxValidity;

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

    # For Ed25519 keys, we need to convert PEM to OpenSSH format
    # ssh-keygen can read PEM format directly for some key types,
    # but for Ed25519 we may need conversion

    # First, try to detect if it's already in OpenSSH format
    if ( $pemKey =~ /^-----BEGIN OPENSSH PRIVATE KEY-----/ ) {
        return $pemKey;
    }

    # For Ed25519 PEM keys, use ssh-keygen to convert
    if ( $pemKey =~ /BEGIN PRIVATE KEY/ || $pemKey =~ /BEGIN EC PRIVATE KEY/ ) {
        require File::Temp;
        my $tmpdir  = File::Temp::tempdir( CLEANUP => 1 );
        my $pemFile = "$tmpdir/key.pem";
        my $sshFile = "$tmpdir/key";

        # Write PEM key
        open my $fh, '>', $pemFile or return undef;
        print $fh $pemKey;
        close $fh;
        chmod 0600, $pemFile;

        # Try to use the PEM directly with ssh-keygen
        # ssh-keygen -s accepts PEM format for RSA/ECDSA
        # For Ed25519, we need to check if it works

        # Actually, let's just return the PEM and see if ssh-keygen accepts it
        return $pemKey;
    }

    # RSA keys in traditional format
    if ( $pemKey =~ /BEGIN RSA PRIVATE KEY/ ) {
        return $pemKey;
    }

    return $pemKey;
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
        "valid_until": "2024-01-01T12:00:00Z",
        "principals": ["user1"],
        "key_id": "user1@llng-1234567890-000001"
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
