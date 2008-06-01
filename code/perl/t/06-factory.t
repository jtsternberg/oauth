use strict;
use warnings;
use Test::More tests => 5;

BEGIN {
    use_ok( 'Net::OAuth' );
}

my $request = Net::OAuth->request('user auth',
    token => 'abcdef',
    callback => 'http://example.com/callback',
    extra_params => {
            foo => 'bar',
    },
);

is($request->to_post_body, 'foo=bar&oauth_callback=http%3A%2F%2Fexample.com%2Fcallback&oauth_token=abcdef');

my $response = Net::OAuth->response('UserAuth',
    token => 'abcdef',
    extra_params => {
            foo => 'bar',
    },
);

is($response->to_post_body, 'foo=bar&oauth_token=abcdef');

$response = Net::OAuth->response('user_auth',
    token => 'abcdef',
    extra_params => {
            foo => 'bar',
    },
);

is($response->to_post_body, 'foo=bar&oauth_token=abcdef');

$response = Net::OAuth->message('user authentication response',
    token => 'abcdef',
    extra_params => {
            foo => 'bar',
    },
);

is($response->to_post_body, 'foo=bar&oauth_token=abcdef');