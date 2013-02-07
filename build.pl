#!perl

use strict;
use warnings;

use FindBin;
use IPC::Cmd 'can_run';
use Getopt::Long;

my $debug   = 0;
my $apxs    = 'apxs2';
my @flags   = qw[-i -a -c -Wl,-Wall -Wl,-lm];
my $my_lib  = 'mod_querystring2cookie.c';
my @inc;
my @link;

GetOptions(
    debug       => \$debug,
    "apxs=s"    => \$apxs,
    "flags=s@"  => \@flags,
    "inc=s@"    => \@inc,
    "link=s@"   => \@link,
) or die usage();

unless( can_run( $apxs ) ) {
    die "Could not find '$apxs' in your path.\n\n" .
        "On Ubuntu/Debian, try 'sudo apt-get install apache2-dev'\n\n";
}

### ap2xs doesn't add apreq2 automatically, so we add it here.
push @inc, '/usr/include/apreq2';

### from apxs man page:
### * -Wl,-lX to link against X
### * -Wc,-DX to tell gcc to -D(efine) X
### * -I to include other dirs

my @cmd = ( $apxs, @flags );

### extra include dirs
push @cmd, map { "-I $_" } $FindBin::Bin, @inc;

### libraries to link against
push @cmd, map { "-Wl,-l$_" } @link;

### enable debug?
push @cmd, "-Wc,-DDEBUG" if $debug;

### our module
push @cmd, $my_lib;


warn "\n\nAbout to run:\n\t@cmd\n\n";

system( @cmd ) and die $?;

sub usage {
    my $me = $FindBin::Script;

    return qq[
  $me [--debug] [--inc /some/dir,..] [--link some_lib]

    \n];
}

