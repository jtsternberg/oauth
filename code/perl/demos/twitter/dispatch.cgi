#!/opt/local/bin/perl

use strict;
use lib qw(/Users/keith/src/oauth/perl/lib);
use CGI::Carp qw(fatalsToBrowser);
use OAuthDemo;
$ENV{OAUTH_DEMO_HOME} = '.' unless defined $ENV{OAUTH_DEMO_HOME};
my $app = OAuthDemo->new();
$app->mode_param( path_info => 1 );
$app->run();
