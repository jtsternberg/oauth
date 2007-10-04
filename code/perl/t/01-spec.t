#!perl -T

use strict;
use warnings;
use Test::More tests => 12;

BEGIN {
    use_ok( 'Net::OAuth::Request' );
	use_ok( 'Net::OAuth::RequestTokenRequest' );
	use_ok( 'Net::OAuth::AccessTokenRequest' );
	use_ok( 'Net::OAuth::ProtectedResourceRequest' );
}

diag( "Testing Net::OAuth $Net::OAuth::Request::VERSION, Perl $], $^X" );

my $request = Net::OAuth::RequestTokenRequest->new(
        consumer_key => 'dpf43f3p2l4k3l03',
        consumer_secret => 'kd94hf93k423kf44',
        request_url => 'https://photos.example.net/request_token',
        request_method => 'POST',
        signature_method => 'PLAINTEXT',
        timestamp => '1191242090',
        nonce => 'hsu94j3884jdopsl',
);

$request->sign;

ok($request->verify);

is($request->to_post_body, 'oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=hsu94j3884jdopsl&oauth_signature=kd94hf93k423kf44%26&oauth_signature_method=PLAINTEXT&oauth_timestamp=1191242090&oauth_version=1.0');

$request = Net::OAuth::AccessTokenRequest->new(
        consumer_key => 'dpf43f3p2l4k3l03',
        consumer_secret => 'kd94hf93k423kf44',
        request_url => 'https://photos.example.net/access_token',
        request_method => 'POST',
        signature_method => 'PLAINTEXT',
        timestamp => '1191242092',
        nonce => 'dji430splmx33448',
        token => 'hh5s93j4hdidpola',
        token_secret => 'hdhd0244k9j7ao03',
);

$request->sign;

ok($request->verify);

is($request->to_post_body, 'oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=dji430splmx33448&oauth_signature=kd94hf93k423kf44%26hdhd0244k9j7ao03&oauth_signature_method=PLAINTEXT&oauth_timestamp=1191242092&oauth_token=hh5s93j4hdidpola&oauth_version=1.0');

$request = Net::OAuth::ProtectedResourceRequest->new(
        consumer_key => 'dpf43f3p2l4k3l03',
        consumer_secret => 'kd94hf93k423kf44',
        request_url => 'http://photos.example.net/photos',
        request_method => 'GET',
        signature_method => 'HMAC-SHA1',
        timestamp => '1191242096',
        nonce => 'kllo9940pd9333jh',
        token => 'nnch734d00sl2jdk',
        token_secret => 'pfkkdhi9sl3r4s00',
        extra_params => {
            file => 'vacation.jpg',
            size => 'original',
        }
);

$request->sign;

ok($request->verify);

is($request->signature_base_string, 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal&kd94hf93k423kf44&pfkkdhi9sl3r4s00');

is($request->signature, 'Gcg/323lvAsQ707p+y41y14qWfY');

is($request->to_authorization_header('http://photos.example.net/authorize', ",\n")."\n", <<EOT);
OAuth realm="http://photos.example.net/authorize",
oauth_consumer_key="dpf43f3p2l4k3l03",
oauth_nonce="kllo9940pd9333jh",
oauth_signature="Gcg%2F323lvAsQ707p%2By41y14qWfY",
oauth_signature_method="HMAC-SHA1",
oauth_timestamp="1191242096",
oauth_token="nnch734d00sl2jdk",
oauth_version="1.0"
EOT

