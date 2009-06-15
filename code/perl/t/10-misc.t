use strict;
use warnings;
use Test::More tests => 4;

BEGIN {
    use Net::OAuth;
    $Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0;
}

my $request = Net::OAuth->request('user auth')->new(
    token => 'abcdef',
    callback => 'http://example.com/callback',
    extra_params => {
            foo => 'bar',
    },
);

is($request->to_post_body, 'foo=bar&oauth_callback=http%3A%2F%2Fexample.com%2Fcallback&oauth_token=abcdef');

use URI;
my $url = URI->new('http://example.com?bar=baz');
is($request->to_url($url), 'http://example.com?foo=bar&oauth_callback=http%3A%2F%2Fexample.com%2Fcallback&oauth_token=abcdef');
is($url, 'http://example.com?bar=baz');

$request = Net::OAuth->request('Request Token')->new(
		consumer_key => 'dpf43f3p2l4k3l03',
        signature_method => 'PLAINTEXT',
        timestamp => '1191242090',
        nonce => 'hsu94j3884jdopsl',
    	consumer_secret => 'kd94hf93k423kf44',
    	request_url => 'https://photos.example.net/request_token',
    	request_method => 'GET',
    	extra_params => {
    	    foo => 'this value contains spaces'
    	},
);


is($request->to_url(), 'https://photos.example.net/request_token?foo=this%20value%20contains%20spaces&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=hsu94j3884jdopsl&oauth_signature=&oauth_signature_method=PLAINTEXT&oauth_timestamp=1191242090&oauth_version=1.0');
