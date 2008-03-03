#!/usr/bin/env perl

use strict;
use warnings;

#use Smart::Comments;
use FindBin;
use lib "$FindBin::Bin/../lib";
use OpenResty::Dispatcher;
use OpenResty::Limits;
use Getopt::Std;

my $cmd = lc(shift) || $ENV{OPENAPI_COMMAND} || 'fastcgi';
$ENV{OPENAPI_COMMAND} = $cmd;

eval {
    OpenResty::Dispatcher->init;
};
warn $@ if $@;

if ($cmd eq 'fastcgi') {
    require OpenResty::FastCGI;
    while (my $cgi = new OpenResty::FastCGI) {
        eval {
            OpenResty::Dispatcher->process_request($cgi);
        };
        if ($@) {
            warn $@;
            print "HTTP/1.1 200 OK\n";
            # XXX don't show $@ to the end user...
            print qq[{"success":0,"error":"$@"}\n];
        }
    }
    exit;
} elsif ($cmd eq 'cgi') {
    require CGI::Simple;
    my $cgi = CGI::Simple->new;
    OpenResty::Dispatcher->process_request($cgi);
    exit;
} elsif ($cmd eq 'start') {
    my %opts;
    getopts('p:', \%opts);
    my $port = $opts{p} || 8000;

    require OpenResty::Server;
    my $server = OpenResty::Server->new;
    $server->port($port);
    $server->run;
    exit;
}

my $error = $OpenResty::Dispatcher::InitFatal;
if ($error) {
    die $error;
}
my $backend = $OpenResty::Backend;

if ($cmd eq 'adduser') {
    my $user = shift or
        die "No user specified.\n";
    if ($backend->has_user($user)) {
        die "User $user already exists.\n";
    }
    eval "use Term::ReadKey;";
    if ($@) { die $@; }
    local $| = 1;

    my $password;
    print "Enter the password for the Admin role: ";

    ReadMode(2);
    my $key;
    while (not defined ($key = ReadLine(0))) {
    }
    ReadMode(0);

    $key =~ s/\n//s;
    print "\n";

    my $saved_key = $key;
    #warn "Password: $password\n";
    OpenResty::check_password($saved_key);

    print "Re Enter the password for the Admin role: ";

    ReadMode(2);
    while (not defined ($key = ReadLine(0))) {
    }
    ReadMode(0);

    $key =~ s/\n//s;
    print "\n";

    if ($key ne $saved_key) {
        die "2 passwords don't match.\n";
    }
    $password = $key;

    $OpenResty::Backend->add_user($user, $password);
    my $machine = $OpenResty::Backend->has_user($user);
    if ($machine) {
        warn "User $user created on node $machine.\n";
    }
} elsif ($cmd eq 'deluser') {
    my $user = shift or
        die "No user specified.\n";
    if ($backend->has_user($user)) {
        $OpenResty::Backend->drop_user($user);
    } else {
        die "User $user does not exist.\n";
    }
} else {
    die "Unknown command: $cmd\n";
}



