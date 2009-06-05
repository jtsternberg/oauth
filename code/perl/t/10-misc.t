use strict;
use warnings;
use Test::More tests => 3;

BEGIN {
    use_ok( 'Net::OAuth' );
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
