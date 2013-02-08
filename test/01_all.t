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
my $DefaultName         = 'qs2cookie';  # as set as the module default
my $DefaultQueryString  = 'a=1&b=2&c';

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
        qs          => '',
        no_cookie   => 1,
    },

    ### We url encode keys/values that go into cookies
    'basic/url_escape' => {
        qs      => 'a=/&/=42&b=;&;=42&c=@&@=42',
        expect  => { a => '%2F', '%2F' => 42,
                     b => '%3B', '%3B' => 42,
                     c => '%40', '%40' => 42,
                   },
    },

    ### straight forward conversion
    basic   => { },

    ### use a different domain
    domain  => {
        domain  => '.example.com',
    },

    ### lower the expires time
    expires => {
        expires => 120,
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
    },

    ### use a different cookie name
    cookie_name => {
        cookie_name => 'cookie_name',
    },

    ### don't get the default name, get it from a query string
    cookie_name_from => {
        cookie_name => 'cookie_name',
        qs          => "cookie_name_from=cookie_name&". $DefaultQueryString,
        expect      => { a => 1, b => 2 },
    },

    ### if we dont have the cookie_name_from in the query string, we should
    ### not get a cookie and an error header should be set.
    "cookie_name_from/missing_query_param" => {
        no_cookie   => 1,
        expect      => sub {
            my $res             = shift;
            my $parsed_cookie   = shift || {};

            ### required query param not present - we shouldn't have a cookie
            ok( !scalar(keys(%$parsed_cookie)),
                                "   No cookie returned" );

            ### we should however have an error message
            my ($err) = $res->header( 'X-QS2Cookie' );
            ok( $err,           "   Error message set: $err" );
            like( $err, qr/missing QS argument/i,
                                "       Error message as expected" );

        },
    },

     ### use different delimiters in the cookie value
     delimiters => {
         cookie_pair_delimiter       => ',',
         cookie_key_value_delimiter  => '-',
     },

     ### use a different encoding style, namely in the key, not the value
     encode_in_key => {
         expect  => sub {
             ### The parsing routine will turn this:
             ### qs2cookie^a|1^b|2=1344326082; path=/; expires=Wed, 08-Aug-12 07:54:42 GMT
             ### into this (the value is the timestamp in seconds of when it's set):
             ### 'qs2cookie^a|1^b|2' => { '1344326082' => undef }

             my $res             = shift;
             my $parsed_cookie   = shift;
             my $key             = 'qs2cookie^a|1^b|2';

             ok( exists $parsed_cookie->{$key},  "   Key $key exists" );

             my $href            = $parsed_cookie->{$key};
             isa_ok( $href,              "HASH", "       Value" );
             is( scalar(keys(%$href)),   1,      "       Sub hash has 1 key" );

             my $val             = [ keys %$href ]->[0];
             ok( $val,                           "       Value exists: $val" );
             like( $val, qr/^\d+$/,              "           All digits" );
             cmp_ok( $val, '<=', time + 5,       "           Older than 5 secs from now" );
             cmp_ok( $val, '>=', time - 5,       "           Younger than 5 secs ago" );
         },
     },
);



for my $endpoint ( sort keys %Map ) {

    my $cfg = $Map{ $endpoint };

    ### Defaults in case not provided
    my $qs          = exists $cfg->{qs} ? $cfg->{qs} : $DefaultQueryString;
    my $header      = $cfg->{header}        || [ ];
    my $prefix      = $cfg->{prefix}        || '';
    my $expires     = $cfg->{expires}       || undef;
    my $domain      = $cfg->{domain}        || '';              # unset by default
    my $expect      = $cfg->{expect}        || undef;
    my $cookie_name = $cfg->{cookie_name}   || $DefaultName;

    my $cookie_pair_delimiter
                    = quotemeta( $cfg->{cookie_pair_delimiter} || '^' );
    my $cookie_key_value_delimiter
                    = quotemeta( $cfg->{cookie_key_value_delimiter} || '|' );

    ### build the test
    my $url     = "$Base/$endpoint";
    $url       .= "?$qs" if $qs;
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
    my $parsed_cookie;
    if( $cfg->{no_cookie} ) {
        is_deeply( [ ], [ $res->header( 'Set-Cookie' ) ],
                    "   No cookies expected, none returned" );

        ### all other tests are pointless, or even invalid, after this, so skip.
        ### unless you gave us an expect routine of course
        next unless $expect;
    } else {

        ### this should only send back ONE set cookie header
        my @cookies = $res->header( 'Set-Cookie' );

        is( scalar( @cookies ), 1,
                        "   Exactly one cookie header returned: @cookies" );

        ### parse out the cookie values, quick and dirty
        $parsed_cookie = _parse_cookie(
                                $cookies[0],
                                $cookie_pair_delimiter,
                                $cookie_key_value_delimiter,
                            );

    }

    ### custom subroutine?
    if( UNIVERSAL::isa( $expect, 'CODE' ) ) {
        $expect->( $res, $parsed_cookie );

    ### just a plain hash?
    } else {

        ### valide the key/value pairs are as expected
        my $rv = _validate_cookie( $url, $parsed_cookie, $prefix, $expect,
                                    $cookie_name );
    }

    ### check meta variables - only applies if cookies are supposed to be returned
    if( $qs and !$cfg->{no_cookie} ) {

        ### expires set explicitly?
        if( $expires ) {
            my $t = str2time( $parsed_cookie->{meta}->{expires} );
            cmp_ok( ($t - time - 10), '<=', $expires,
                "   Expires set to at least $expires -10 seconds in the future" );

            cmp_ok( ($t - time + 10), '>=', $expires,
                "   Expires set to no more than $expires +10 seconds in the future" );
        } else {
            ok( !exists($parsed_cookie->{meta}->{expires}),
                "   Expires time NOT set" );
        }

        ### domain
        is( ($parsed_cookie->{meta}->{domain} || ''), $domain,
                    "   Domain is set to: ". ($domain ? $domain : "<empty>" ));

        ### path - not configurable
        is( $parsed_cookie->{meta}->{path}, '/',
                    "   Path is set to: /" );
    }
}

### A cookie will look like this:
### Set-Cookie: prefix_$defaultname=key1|val1^key2|val2; path.. ; domain.. ; expires..
sub _parse_cookie {
    my $cookie      = shift;
    my $pair_delim  = shift;
    my $kv_delim    = shift;
    my $rv          = { };

    diag "Returned cookie: $cookie" if $Debug;

    for my $kv ( split( /;\s*/, $cookie ) ) {
        my($k,$v) = split( /=/, $kv );

        ### What type of variable? We're overriding the meta variables,
        ### but that's ok, they're the same for all cookies anyway
        if( $k =~ /path|domain|expires/i ) {
            $rv->{'meta'}->{$k} = $v;

        } else {

            ### split the value up. Format is:
            ### key1|val1^key2|val2
            for my $pair ( split /$pair_delim/, $v ) {
                my($key, $val) = split /$kv_delim/, $pair;

                $rv->{ $k }->{ $key } = $val;
            }
        }
    }

    diag "Parsed cookie: ". Dumper( $rv ) if $Debug;

    return $rv;
}

sub _validate_cookie {
    my $url         = shift;
    my $pc          = shift;
    my $pre         = shift || '';
    my $expect      = shift;
    my $cookie_name = shift;
    my $cookie_name_from
                    = shift;

    ### for ?a=1&b it will have { a => 1, b => '' }. Filter out b as that
    ### is not how our module behaves. Also prepend with the prefix, if
    ### there was one.
    my %qs  = URI->new( $url )->query_form;
    my %fqs = $expect
                ? %$expect
                : map  { $_->[0] => $_->[1] }
                  grep { $_->[1] }
                  map  { [ $_ => $qs{$_} ] } keys %qs;

    diag "Unfiltered cookie: ". Dumper( \%qs )  if $Debug;

    diag "Filtered cookie: ".   Dumper( \%fqs ) if $Debug;

    is_deeply( $pc->{ $pre . $cookie_name }, \%fqs,
                        "   Cookie pairs match query string" );
}
