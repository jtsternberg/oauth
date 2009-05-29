Twitter Net::OAuth Demo
=======================

Dependencies
------------

Perl 5.8+

CGI::Application
CGI::Application::Plugin::AutoRunmode
CGI::Application::Plugin::TT
CGI::Application::Plugin::Session
CGI::Application::Plugin::Config::YAML
Net::OAuth
File::Slurp
Data::Random
LWP::UserAgent
HTTP::Request::Common
XML::LibXML

Registration
------------

You need to register an app with Twitter, and write the consumer key and consumer secret for
config.yml file.  The callback for your app should be http://mydomain.example.com/callback or 
http://mydomain.example.com/dispatch.cgi/callback depending on your setup (see below).

Installation
------------

Super simple:

* Unzip files under the document root of a virtual host domain
* Edit settings in config.yml 
** If you have mod_rewrite, the base_url should be http://mydomain.example.com
** If not, the base_url should be http://mydomain.example.com/dispatch.cgi

A little less simple:

* Put dispatch.cgi under your document root (say, in a cgi-bin)
* Set the OAUTH_DEMO_HOME environment variable to point to the dir containing all the other files
* Edit settings in config.yml
** Your base url will be the URL to the wherever you put dispatch.cgi
