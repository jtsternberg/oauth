#!perl -T

use strict;
use warnings;
use Test::More tests => 2;
use UNIVERSAL::require;

use Net::OAuth::ProtectedResourceRequest;

sub slurp {
    my $file = shift;
    my $text = do { local( @ARGV, $/ ) = $file ; <> } ;
    return $text;
}

SKIP: {
    
    skip "Crypt::OpenSSL::RSA not installed", 2 unless Crypt::OpenSSL::RSA->require;

    my $publickey;
    my $privkey;

    eval {
    $privkey = Crypt::OpenSSL::RSA->new_private_key(slurp('t/rsakey'));
    } or die "unable to read private key";
    eval {
    $publickey = Crypt::OpenSSL::RSA->new_public_key(slurp("t/rsakey.pub"));
    } or die "unable to read public key";

    my $request = Net::OAuth::ProtectedResourceRequest->new(
            consumer_key => 'dpf43f3p2l4k3l03',
            consumer_secret => 'kd94hf93k423kf44',
            request_url => 'http://photos.example.net/photos',
            request_method => 'GET',
            signature_method => 'RSA-SHA1',
            timestamp => '1191242096',
            nonce => 'kllo9940pd9333jh',
            token => 'nnch734d00sl2jdk',
            token_secret => 'pfkkdhi9sl3r4s00',
            extra_params => {
                file => 'vacation.jpg',
                size => 'original',
            },
            signature_key => $privkey,
    );

    $request->sign;
    is($request->signature, "IqaxX6ickh5dUfon2YvSqzDrBKGhO0d1zy+NCqeDR+FRyoECm+MYUGvLAsgGRkj7FqHF/8wbaJFL1eyVQcGqJIR79l18iulfRcS0oqb6kIndbIQ0a3zZq2gwWJ95+EY1mvtQF07lN19xuRsq6qQi7Y1iuTFqgs5+Jzlg2cCPjZiTTPdIS/Ww8V0vEBJemrtWiWr8KwOXYi99D1O0mH17+v9nS5xXt3zj1QqA/FKu1CIuDT2n3KW7fAZhN7Ol7tSSz/RiuvGrAP8ASnETxouYbd9Al3zpetMkQsY2ZLu68pKI9O96mqn/b13Ug8zwKIHXNvahrX2KVOiBXY5kbV4fFg==");
    ok($request->verify($publickey));

}

