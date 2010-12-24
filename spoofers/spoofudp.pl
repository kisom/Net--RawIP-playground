#!/usr/bin/env perl

use warnings;
use strict;
use Net::RawIP;

my $src = $ARGV[0] or &usage();
my $dst = $ARGV[1] or &usage();
my $str = $ARGV[2] or &usage();

my $rawpkt  = new Net::RawIP({
    ip => {
        saddr => $src,
        daddr => $dst
    },
    #udp => { }
    udp => {
        source  => 10001,
        dest    => 53,
        data    => $str
    }}
);

#$rawpkt->set({ 
#    ip => {
#        saddr   => $src,
#        daddr   => $dst
#    },
#    udp => {
#        source  => 10001,
#        dest    => 53,
#        data    => $str
#    }
#});

$rawpkt->send();

print '[+] sent '. length($str) . " bytes of data...\n";
exit 0;


sub usage() {
    die "usage: $0 <src> <dst> <str>";
}

