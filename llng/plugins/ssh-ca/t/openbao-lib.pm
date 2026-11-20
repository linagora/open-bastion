# Mock of OpenBao's AppRole login and SSH secrets engine, for the
# sshCaSigner = openbao tests (issue #476).
#
# Requests to http://bao.test are routed to a PSGI app (LWP::Protocol::PSGI)
# that REALLY signs with `ssh-keygen -s` and a CA key it holds, so the
# plugin's certificate parsing and validation run on genuine certificates.
# It honours valid_principals, ttl, key_id and critical_options, picks a
# random 64-bit serial (-z) and answers like OpenBao:
#   {"data":{"serial_number":"<hex>","signed_key":"<type> <base64>\n"}}
#
# The same file is shipped in ssh-ca/t and pam-access/t: keep both copies
# identical.
package openbao_lib;

use strict;
use warnings;
use JSON       qw(to_json from_json);
use File::Temp qw(tempdir);
use Math::BigInt;

our $HOST = 'bao.test';
our $URL  = "http://$HOST";

# Mock state, reset by reset_state():
#   role_id, secret_id : accepted AppRole credentials
#   lease              : lease_duration announced for the tokens it issues
#   token_ttl          : how long they are really accepted
#   tokens             : token => expiry
#   requests           : [ { method, path, body, token } ]
#   signed             : [ { serial (decimal), ... } ] what was really signed
#   fail_login         : [ code, body ] answered to every login
#   fail_sign          : [ code, body ] answered to every sign
#   fail_sign_once     : same, once
#   tamper             : changes applied to the next signatures (see sign())
#   public_key         : body of /public_key (default: the CA public key)
our %S;
my ( $dir, %ca );

sub deps_ok {
    return eval {
        require LWP::Protocol::PSGI;
        require Plack::Request;
        1;
    };
}

# Generate the CA key pairs ('main' signs, 'other' is a rogue CA) and route
# http://bao.test to the mock. Returns 0 if ssh-keygen is unusable.
sub setup {
    $dir = tempdir( CLEANUP => 1 );
    for my $name (qw(main other)) {
        system(
            'ssh-keygen', '-q', '-t', 'ed25519',
            '-N',         '',   '-C', "bao-$name-ca",
            '-f',         "$dir/$name"
          ) == 0
          or return 0;
        $ca{$name} = "$dir/$name";
    }
    reset_state();
    LWP::Protocol::PSGI->register( \&app, host => $HOST );
    return 1;
}

# Use another private key as the 'main' CA (e.g. a PEM RSA key).
sub use_ca_key {
    my ($pem) = @_;
    my $f = "$dir/main-custom";
    open my $fh, '>', $f or die;
    print $fh $pem;
    close $fh;
    chmod 0600, $f;
    $ca{main} = $f;
}

sub reset_state {
    %S = (
        role_id   => 'portal-role',
        secret_id => 's3cret-id',
        lease     => 3600,
        token_ttl => 3600,
        tokens    => {},
        requests  => [],
        signed    => [],
        tamper    => {},
    );
}

sub ca_pub {
    my ($name) = @_;
    my $key = $ca{ $name || 'main' };
    return scalar `ssh-keygen -y -f $key` unless -f "$key.pub";
    open my $fh, '<', "$key.pub" or die;
    my $l = <$fh>;
    close $fh;
    return $l;
}

sub requests       { return @{ $S{requests} } }
sub clear_requests { $S{requests} = [] }

sub paths {
    return map { "$_->{method} $_->{path}" } @{ $S{requests} };
}

sub _json {
    my ( $code, $body ) = @_;
    return [
        $code,
        [ 'Content-Type' => 'application/json' ],
        [ ref $body ? to_json($body) : $body ]
    ];
}

sub app {
    my ($env) = @_;
    my $req   = Plack::Request->new($env);
    my $raw   = $req->content            // '';
    my $body  = eval { from_json($raw) } // $raw;
    my $token = $req->header('X-Vault-Token');
    my $path  = $req->path_info;
    push @{ $S{requests} },
      {
        method => $req->method,
        path   => $path,
        body   => $body,
        token  => $token,
      };

    if ( $req->method eq 'POST' and $path =~ m{\A/v1/auth/([^/]+)/login\z} ) {
        return _json( @{ $S{fail_login} } ) if $S{fail_login};
        unless ( ref $body eq 'HASH'
            and ( $body->{role_id}   // '' ) eq $S{role_id}
            and ( $body->{secret_id} // '' ) eq $S{secret_id} )
        {
            return _json( 400, { errors => ['invalid role or secret ID'] } );
        }
        my $t = 'hvs.' . join '', map { sprintf '%02x', int rand 256 } 1 .. 12;
        $S{tokens}{$t} = time + $S{token_ttl};
        return _json(
            200,
            {
                auth => {
                    client_token   => $t,
                    lease_duration => $S{lease},
                    renewable      => JSON::true,
                    policies       => ['llng-portal'],
                }
            }
        );
    }

    if ( $req->method eq 'GET' and $path =~ m{\A/v1/(.+)/public_key\z} ) {
        return $S{fail_public_key} if $S{fail_public_key};
        return [
            200,
            [ 'Content-Type' => 'text/plain' ],
            [ $S{public_key} // ca_pub('main') ]
        ];
    }

    if ( $req->method eq 'POST' and $path =~ m{\A/v1/(.+)/sign/([^/]+)\z} ) {
        unless ( defined $token
            and $S{tokens}{$token}
            and $S{tokens}{$token} > time )
        {
            return _json( 403, { errors => ['permission denied'] } );
        }
        return _json( @{ delete $S{fail_sign_once} } ) if $S{fail_sign_once};
        return _json( @{ $S{fail_sign} } )             if $S{fail_sign};
        return sign($body);
    }

    return _json( 404, { errors => ["no handler for route '$path'"] } );
}

# Sign like OpenBao's SSH engine. $S{tamper} keys, to play a misconfigured
# or hostile OpenBao:
#   ca          => 'other'           sign with the rogue CA
#   key         => '<pubkey line>'   certify another key
#   principals  => 'a,b'             -n value
#   key_id      => '...'             -I value
#   source      => '<addr>' or ''    source-address (empty: drop it)
#   ttl         => '+<n>s'           -V value
#   options     => [ '-O' values ]   extra options
#   host        => 1                 sign a host certificate
#   serial      => '<decimal>'       serial to sign with
#   serial_hex  => '<hex>'           serial_number to announce
#   signed_key  => '<string>'        raw signed_key to answer
#   response    => <body>            raw `data` content to answer
sub sign {
    my ($body) = @_;
    my $t = $S{tamper};
    return _json( 400, { errors => ['bad body'] } ) unless ref $body eq 'HASH';
    return _json( 200, { data   => $t->{response} } ) if exists $t->{response};

    my $d = tempdir( CLEANUP => 1 );
    open my $fh, '>', "$d/user.pub" or die;
    print $fh ( $t->{key} // $body->{public_key} ), "\n";
    close $fh;

    my $ttl = $body->{ttl} // '';
    $ttl =~ /\A[0-9]+[smhd]\z/
      or return _json( 400, { errors => ["invalid ttl '$ttl'"] } );

    my $serial = $t->{serial} // Math::BigInt->from_hex( join '',
        map { sprintf '%02x', int rand 256 } 1 .. 8 )->bstr;

    my @cmd = (
        'ssh-keygen', '-q',
        '-s',         $ca{ $t->{ca} || 'main' },
        '-I',         $t->{key_id} // $body->{key_id} // 'token-display-name',
        '-n',         $t->{principals} // $body->{valid_principals},
        '-V',         $t->{ttl}        // "+$ttl",
        '-z',         $serial,
    );
    my $source =
      exists $t->{source} ? $t->{source}
      : (
        ref $body->{critical_options} eq 'HASH'
        ? $body->{critical_options}{'source-address'}
        : undef
      );
    push @cmd, '-O', "source-address=$source"
      if defined $source && length $source;
    push @cmd, map { ( '-O', $_ ) } @{ $t->{options} || [] };
    push @cmd, '-h' if $t->{host};
    push @cmd, "$d/user.pub";

    system(@cmd) == 0
      or return _json( 500, { errors => ['ssh-keygen failed'] } );
    open $fh, '<', "$d/user-cert.pub" or die;
    my $line = <$fh>;
    close $fh;

    # OpenBao answers "<type> <base64>\n", without the key comment.
    my ( $type, $b64 ) = split /\s+/, $line;
    push @{ $S{signed} }, { serial => "$serial", body => $body };

    return _json(
        200,
        {
            request_id => 'c0ffee',
            data       => {
                serial_number => $t->{serial_hex}
                  // substr( Math::BigInt->new($serial)->as_hex, 2 ),
                signed_key => $t->{signed_key} // "$type $b64\n",
            },
            warnings => undef,
        }
    );
}

1;
