mod_querystring2cookie
======================

Convert query string parameters into a cookie

############################
### Building
############################

Make sure you have apxs2 and perl installed, which on Ubuntu
you can get by running:

  $ sudo apt-get install apache2-dev libapreq2-dev perl

From the checkout directory run:

  $ sudo ./build.pl

This will build, install & enable the module on your system

############################
### Configuration
############################

See the file 'DOCUMENTATION' in the same directory as this
README for all the extra features this module has compared to
mod_usertrack, as well as documentation on the configuration
directives supported.

############################
### Testing
############################

*** Note: for this will you will need Apache, NodeJS
*** and Perl installed.

First, start the backend node based server. It serves
as an endpoint and shows you the received url & headers
for every call:

  $ test/run_backend.sh

Next, start a custom Apache server. This will have all
the modules needed and the endpoints for testing:

  $ sudo test/run_httpd.sh

Then, run the test suite:

  $ perl test/01_all.pl

Run it as follows to enable diagnostic/debug output:

  $ perl test/01_all.pl --debug

There will be an error log available, and that will be
especially useful if you built the library with --debug:

  $ tail -F test/error.log



