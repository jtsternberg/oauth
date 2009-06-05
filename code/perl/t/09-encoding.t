#!perl

use strict;
use warnings;
use Test::More tests => 20;
use Encode;

BEGIN {
        use_ok( 'Net::OAuth::Message' );
}

use utf8;

sub is_encoding {
    my $orig = shift;
    my $encoded = shift;
    is(Net::OAuth::Message::encode($orig), $encoded);
}

is_encoding('abcABC123', 'abcABC123');
is_encoding('-._~', '-._~');
is_encoding('%', '%25');
is_encoding('+', '%2B');
is_encoding(' ', '%20');
is_encoding('&=*', '%26%3D%2A');
is_encoding("\x{000A}", '%0A');
is_encoding("\x{0020}", '%20');
is_encoding("\x{007F}", '%7F');
is_encoding("\x{0080}", '%C2%80');
is_encoding("\x{2708}", '%E2%9C%88');
is_encoding("\x{3001}", '%E3%80%81');
is_encoding("\x{2708}", '%E2%9C%88');
is_encoding("\x{00A0}", '%C2%A0');
is_encoding("\x{00E7}", '%C3%A7');
is_encoding("ç", '%C3%A7');
is_encoding("æ", '%C3%A6');

my $warning = '';
$SIG{__WARN__} = sub {$warning = shift};
is_encoding(Encode::encode_utf8("\x{00E7}"), '%C3%83%C2%A7');
ok($warning =~ /^Warning: It looks like you are attempting to encode bytes that are already UTF-8 encoded/);
