package Net::OAuth;
use warnings;
use strict;
use UNIVERSAL::require;

our $VERSION = '0.07';

sub request {
    my $self = shift;
	my $what = shift;
    return $self->message($what . ' Request', @_);
}

sub response {
    my $self = shift;
	my $what = shift;
    return $self->message($what . ' Response', @_);
}

sub message {
    my $self = shift;
    my $type = camel(shift);
    my $class = 'Net::OAuth::' . $type;
    $class->require;
    my $msg = $class->new(@_);
    return $msg;
}

sub camel {
	my @words;
	foreach (@_) {
		while (/([A-Za-z0-9]+)/g) {
			(my $word = $1) =~ s/authentication/auth/i;
			push @words, $word;
		}
	}
	my $name = join('', map("\u$_", @words));
}

=head1 NAME

Net::OAuth - OAuth protocol support

=head1 SYNOPSIS

	# Consumer sends Request Token Request

	use Net::OAuth;

	my $request = Net::OAuth->request("request token"
        consumer_key => 'dpf43f3p2l4k3l03',
        consumer_secret => 'kd94hf93k423kf44',
        request_url => 'https://photos.example.net/request_token',
        request_method => 'POST',
        signature_method => 'PLAINTEXT',
        timestamp => '1191242090',
        nonce => 'hsu94j3884jdopsl',
		extra_params => {
			apple => 'banana',
			kiwi => 'pear',
		}
	);

	$request->sign;

	$response = POST($request->to_url); # Post message to the Service Provider

	# Service Provider receives Request Token Request
	
	use Net::OAuth;
	use CGI;

	my $request = Net::OAuth->request("request token", %{$q->Vars});

	if (!$request->verify) {
		die "Signature verification failed";
	}
	else {
		# Service Provider sends Request Token Response

		my $response = Net::OAuth->response("request token", 
			token => 'abcdef',
			token_secret => '0123456',
		);

		print $response->to_post_body;
	}	

	# Etc..

=head1 ABSTRACT

OAuth is 

"An open protocol to allow secure API authentication in a simple and standard method from desktop and web applications."

In practical terms, OAuth is a mechanism for a Consumer to request protected resources from a Service Provider on behalf of a user.

Please refer to the OAuth spec: L<http://oauth.net/documentation/spec>

Net::OAuth provides:

=over

=item * classes that encapsulate OAuth messages (requests and responses).  

=item * message signing

=item * message serialization and parsing.

=back

Net::OAuth does not provide:

=over

=item * Consumer or Service Provider encapsulation  

=item * token/nonce/key storage/management

=back

=head1 DESCRIPTION

=head2 OAUTH MESSAGES

An OAuth message is a set of key-value pairs.  The following message types are supported:

Requests

=over

=item * Request Token (Net::OAuth::RequestTokenRequest)

=item * Access Token (Net::OAuth::AccessTokenRequest)

=item * User Authentication (Net::OAuth::UserAuthRequest)

=item * Protected Resource (Net::OAuth::ProtectedResourceRequest)

=back

Responses

=over

=item * Request Token (Net::OAuth::RequestTokenResponse)

=item * Access Token (Net::OAuth:AccessTokenResponse)

=item * User Authentication (Net::OAuth::UserAuthResponse)

=back

Each OAuth message type has one or more REQUIRED parameters, zero or more OPTIONAL parameters, and most allow arbitrary parameters.

All OAuth requests must be signed by the Consumer.  Responses, however, are not signed.

To create a message, the easiest way is to use the factory methods (Net::OAuth->request, Net::OAuth->response, Net::OAuth->message).  The following method invocations are all equivalent:

 $request = Net::OAuth->request('user authentication', %params);
 $request = Net::OAuth->request('user_auth', %params);
 $request = Net::OAuth->request('UserAuth', %params);
 $request = Net::OAuth->message('UserAuthRequest', %params);

You can also instantiate the class directly:

 $request = Net::OAuth::UserAuthRequest->new(%params);

Or parse an OAuth Authorization header:

 $request = Net::OAuth::ProtectedResourceRequest->from_authorization_header($header);

Before sending a request, the Consumer must first sign it:

 $request->sign;

When receiving a request, the Service Provider should first verify the signature:

 $request->verify;

When sending a message the next step is to serialize it and send it to wherever it needs to go.  The following serialization methods are available:

 $message->to_post_body # a application/x-www-form-urlencoded POST body

 $message->to_url # the query string of a URL

 $message->to_authorization_header # the value of an HTTP Authorization header

=head2 SIGNATURE METHODS

The following signature methods are supported:

=over

=item * PLAINTEXT

=item * HMAC_SHA1

=item * RSA_SHA1

=back

The signature method is determined by the value of the signature_method parameter that is passed to the message constructor.

If an unknown signature method is specified, the signing/verification will throw an exception.

=head3 PLAINTEXT SIGNATURES

This method is a trivial signature which adds no security.  Not recommended.

=head3 HMAC_SHA1 SIGNATURES

This method is available if you have Digest::HMAC_SHA1 installed.  This is by far the most commonly used method.

=head3 RSA_SHA1 SIGNATURES

To use RSA_SHA1 signatures, pass in a Crypt::OpenSSL::RSA object (or any object that can do $o->sign($str) and $o->verify($str, $sig))

E.g.

Consumer:

 use Crypt::OpenSSL::RSA;
 use File::Slurp qw(slurp);
 $privkey = Crypt::OpenSSL::RSA->new_private_key(slurp('rsakey'));
 $request = Net::OAuth->request('request token', %params);
 $request->sign($privkey);
 
Service Provider:

 use Crypt::OpenSSL::RSA;
 use File::Slurp qw(slurp);
 $publickey = Crypt::OpenSSL::RSA->new_public_key(slurp("rsakey.pub"));
 $request = Net::OAuth->request('request token', %params);
 if (!$request->verify($publickey)) {
 	die "Signature verification failed";
 }

Note that you can pass the key in as a parameter called 'signature_key' to the message constructor, rather than passing it to the sign/verify method, if you like.

=head1 SEE ALSO

L<http://oauth.net>

=head1 AUTHOR

Keith Grennan, C<< <kgrennan at cpan.org> >>

=head1 COPYRIGHT & LICENSE

Copyright 2007 Keith Grennan, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;