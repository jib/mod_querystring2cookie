#!/usr/bin/perl

### XXX run out of semaphores? Can happen in testing:
### ipcs  | grep 0x0 | awk '{print $2}' | xargs -I% ipcrm -s %

use strict;
use warnings;
use Test::More      'no_plan';
use HTTP::Date      qw[str2time];
use Getopt::Long;
use Data::Dumper;
use HTTP::Cookies;
use LWP::UserAgent;

my $Base                = "http://localhost:7000";
my $Debug               = 0;
my $DefaultQueryString  = "a=1&b=2&c";
my $DefaultExpires      = 86400;    # as set as the module default

GetOptions(
    'base=s'            => \$Base,
    'debug'             => \$Debug,
);


my %Map     = (
    ### module is not turned on
    none    => {
        no_cookie   => 1,
    },

    ### This should not return cookies
    "basic/no_query_string" => {
        qs  => '',
    },

    ### straight forward conversion
    basic   => { },

    ### use a different domain
    domain  => {
        domain  => '.example.com',
    },

    ### prefix the cookie values
    prefix  => {
        prefix  => 'prefix_',
    },

    ### limit the size of the returned cookies
    max_size => {
        expect  => { a => 1 },
    },

    ### sending a dnt header - no cookie should be returned
    "basic/sending_dnt_header" => {
        header      => [ DNT => 1 ],
        no_cookie   => 1,
    },

    ### sending a dnt header, but this time the module is enabled anyway
    enable_on_dnt => {
        header      => [ DNT => 1 ],
    },

    ### some keys are supposed to be ignored, case insensitive
    ignore => {
        qs      => $DefaultQueryString .
                    "&ignore=3&DiScArd=4&do_not_ignore=42&ignore_me_not=21",
        expect  => { a => 1, b => 2, do_not_ignore => 42, ignore_me_not => 21 },
    }
);


for my $endpoint ( sort keys %Map ) {

    my $cfg = $Map{ $endpoint };

    ### Defaults in case not provided
    my $qs          = exists $cfg->{qs} ? $cfg->{qs} : $DefaultQueryString;
    my $header      = $cfg->{header}    || [ ];
    my $prefix      = $cfg->{prefix}    || '';
    my $expires     = $cfg->{expires}   || $DefaultExpires;
    my $domain      = $cfg->{domain}    || '';              # unset by default
    my $expect      = $cfg->{expect}    || undef;

    ### build the test
    my $url     = "$Base/$endpoint?$qs";
    my $ua      = LWP::UserAgent->new();
    my @req     = ($url, @$header );

    diag "Sending: @req" if $Debug;

    ### make the request
    my $res     = $ua->get( @req );
    diag $res->as_string if $Debug;

    ### inspect
    ok( $res,                   "Got /$endpoint?$qs" );
    is( $res->code, "204",      "   HTTP Response = 204" );

    ### you don't expect a cookie to come back?
    if( $cfg->{no_cookie} ) {
        is_deeply( [ ], [ $res->header( 'Set-Cookie' ) ],
                    "   No cookies expected, none returned" );

        ### all other tests are pointless, or even invalid, after this, so skip.
        next;
    }

    ### parse out the cookie values, quick and dirty
    my $parsed_cookie = _parse_cookie( $res->header( 'Set-Cookie' ) );

    ### valide the key/value pairs are as expected
    my $rv = _validate_cookie( $url, $parsed_cookie, $prefix, $expect );

    ### check meta variables - only applies if cookies are supposed to be returned
    if( $qs ) {

        {   ### expires
            my $t = str2time( $parsed_cookie->{meta}->{expires} );
            cmp_ok( ($t - time), '<=', $expires,
                    "   Expires set to at least $expires seconds in the future" );

            cmp_ok( ($t - time + 10), '>=', $expires,
                    "   Expires set to no more than $expires +10 seconds in the future" );
        }

        ### domain
        is( $domain, ($parsed_cookie->{meta}->{domain} || ''),
                    "   Domain is set to: ". ($domain ? $domain : "<empty>" ));

        ### path - not configurable
        is( '/', $parsed_cookie->{meta}->{path},
                    "   Path is set to: /" );
    }


}

sub _parse_cookie {
    my @cookies = @_;
    my $rv      = { pairs => {}, meta => {} };

    for my $str (@cookies) {

        diag "Returned cookie: $str" if $Debug;

        for my $kv ( split( /;\s*/, $str ) ) {
            my($k,$v) = split( /=/, $kv );

            ### What type of variable? We're overriding the meta variables,
            ### but that's ok, they're the same for all cookies anyway
            my $cat = $k =~ /path|domain|expires/i ? "meta" : "pairs";
            $rv->{$cat}->{$k} = $v;
        }
    }

    diag "Parsed cookie: ". Dumper( $rv ) if $Debug;


    return $rv;
}

sub _validate_cookie {
    my $url     = shift;
    my $pc      = shift;
    my $pre     = shift || '';
    my $expect  = shift;

    ### for ?a=1&b it will have { a => 1, b => '' }. Filter out b as that
    ### is not how our module behaves. Also prepend with the prefix, if
    ### there was one.
    my %qs  = URI->new( $url )->query_form;
    my %fqs = $expect
                ? %$expect
                : map  { $pre . $_->[0] => $_->[1] }
                  grep { $_->[1] }
                  map  { [ $_ => $qs{$_} ] } keys %qs;

    diag "Unfiltered cookie: ". Dumper( \%qs )  if $Debug;
    diag "Filtered cookie: ".   Dumper( \%fqs ) if $Debug;

    is_deeply( $pc->{'pairs'}, \%fqs, "   Cookie pairs match query string" );
}
