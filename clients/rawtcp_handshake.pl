#!/usr/bin/env perl

use warnings;
use strict;
use Data::Dumper;
use Net::RawIP;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Time::localtime;

# PACKET SETUP
my $src = $ARGV[0] or &usage();
my $dst = $ARGV[1] or &usage();
my $sp  = int(rand(6000)) + 1024;
my $dp  = 4141;
my $mss = pack('n', 16396);
my $syn_seq     = int(rand(2 ** 32) + 1) ;
my $ack_seq     = 0;


# PCAP SETUP
my $err         = '';
my $dev         = Net::Pcap::lookupdev(\$err);
my $dev         = "lo";
my $filter_str  = 'tcp port $dp';
my $filter      = '';
my $snaplen     = 1600 ;
my $timeout     = 5;
my $pcap        = '';
my $sent        = 0;



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
                                seq     => $syn_seq,
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
                                seq     => $syn_seq + 1,
                                ack     => 1,
				psh	=> 1,
                                window  => 32792,
                            }
});
$ack_pkt->optset(
                tcp => {
                    type => [2, 4, 8],
                    data => [ $mss, '', pack('NN', (localtime(), localtime()))]
                }
);

# set up pcap
$pcap = Net::Pcap::pcap_open_live($dev, $snaplen, 1, $timeout, \$err);
Net::Pcap::pcap_setnonblock($pcap, 1, \$err);
#print "got ack $ack_seq\n";

while (! $ack_seq) {
    if (! $sent) {
        print "[+] sending SYN...\n";
        $syn_pkt->send( );
    }
    Net::Pcap::pcap_dispatch($pcap, 1, \&load_ack_seq, '');
}

Net::Pcap::pcap_close($pcap);

$ack_pkt->set({
    tcp => {
        seq     => $syn_seq + 1,
        ack_seq => $ack_seq + 1,
    }
});

print "[+] sending ACK...\n";
$ack_pkt->send();
print "[+] finished!\n";
exit 0;

sub usage( ) {
	die "usage: $0 <src> <dst>\n";
}

sub load_ack_seq {
    my ($data, $hdr, $pkt) = @_ ;

    if (!$pkt || !defined($hdr) || !defined($pkt)) {
        print "[!] no packets captured!\n";
    }

    $pkt = NetPacket::TCP->decode(NetPacket::IP->
              strip(NetPacket::Ethernet->strip($pkt)));
}
