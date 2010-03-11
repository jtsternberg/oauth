#!perl

use strict;
use warnings;
use Test::More tests => 3;

use Net::OAuth;

my $request = Net::OAuth->request('xauth access token')->new(
        consumer_key => 'dpf43f3p2l4k3l03',
        consumer_secret => 'kd94hf93k423kf44',
        request_url => 'https://photos.example.net/access_token',
        request_method => 'POST',
        signature_method => 'PLAINTEXT',
        timestamp => '1191242092',
        nonce => 'dji430splmx33448',
        token => 'hh5s93j4hdidpola',
        token_secret => 'hdhd0244k9j7ao03',
        x_auth_username => 'keeth',
        x_auth_password => 'foobar',
        x_auth_mode => 'client_auth',
);

$request->sign;

ok($request->verify);

is($request->to_post_body, 'oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=dji430splmx33448&oauth_signature=kd94hf93k423kf44%26hdhd0244k9j7ao03&oauth_signature_method=PLAINTEXT&oauth_timestamp=1191242092&oauth_version=1.0&x_auth_mode=client_auth&x_auth_password=foobar&x_auth_username=keeth');

eval {
    $request = Net::OAuth->request('xauth access token')->new(
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
};

ok($@);