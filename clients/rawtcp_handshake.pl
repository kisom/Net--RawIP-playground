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
my $ack_seq     = undef ;


# PCAP SETUP
my $err         = '';
#my $dev         = Net::Pcap::lookupdev(\$err);
my $dev         = "lo";
my $filter_str  = "ip and tcp";
my $filter      = '';
my $snaplen     = 1600 ;
my $timeout     = 0;
my $pcap        = '';
my $sent        = 0;
my ($net, $mask)= '';
Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
printf "net: %x\tmask: %x\n", $net, $mask;



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
                                window  => 32792,
                            }
});
$ack_pkt->optset(
                tcp => {
                    type => [2, 4, 8],
                    data => [ $mss, '', pack('NN', (localtime(), localtime()))]
                }
);

print "[+] building data packet...\n";
my $data_pkt = Net::RawIP->new({
                            ip => {
                                saddr   => $src,
                                daddr   => $dst,
                            },
                            tcp => {
                                source  => $sp,
                                dest    => $dp,
                                seq     => $syn_seq + 1,
                                ack     => 1,
                                psh     => 1,
                                window  => 32792,
                                data    => 'HIHI',
                            }
});
$data_pkt->optset(
            tcp => {
                type => [2, 4],
                data => [ $mss, '' ],
            }
);

# set up pcap
print "[+] opening capture...\n";
$pcap = Net::Pcap::pcap_open_live($dev, $snaplen, 1, $timeout, \$err);
if (Net::Pcap::compile($pcap, \$filter, $filter_str, 0, $mask)) {
    print "[!] error compiling capture filter!\n";
    exit 1;
}

print "[+] setting pcap to nonblocking mode...\n";
Net::Pcap::pcap_setnonblock($pcap, 1, \$err);

while (!defined $ack_seq) {
    if (! $sent) {
        print "[+] sending SYN...\n";
        $syn_pkt->send( );
        $sent = 1;
    }
    Net::Pcap::pcap_dispatch($pcap, 1, \&load_ack_seq, '');
}


$ack_pkt->set({
    tcp => {
        seq     => $ack_seq,
        ack_seq => $syn_seq + 1,
    }
});

$data_pkt->set({
    tcp => {
        seq     => $ack_seq,
        ack_seq => $syn_seq,
    }
});

print "[+] sending ACK...\n";
$ack_pkt->send();

print "[+] sending data...\n";

Net::Pcap::pcap_open_live($dev, $snaplen, 0, 0, \$err);

print "[+] closing pcap...\n";
Net::Pcap::pcap_close($pcap);
print "[+] finished!\n";
exit 0;

sub usage( ) {
	die "usage: $0 <src> <dst>\n";
}

sub load_ack_seq {
    my ($data, $hdr, $pkt) = @_ ;

    if (!$pkt || !defined($hdr) || !defined($pkt)) {
        print "[!] malformed packet!\n";
    }

    my $eth     = NetPacket::Ethernet->decode($pkt) ;
    my $ip      = NetPacket::IP->decode($eth->{data}) ;
    my $tcp     = NetPacket::TCP->decode($ip->{data}) ;

    if ($ip->{proto} != NetPacket::IP::IP_PROTO_TCP) {
        print "[+] INFO: non-TCP packet spotted!\n";
        return undef ;
    }


    my $synack_seq  = $tcp->{seqnum} ;
    my $synack_ack  = $tcp->{acknum} ;
    my $tcp_flags   = $tcp->{flags}  ;
    print "[+] TCP packet - SEQ: $synack_seq FLAGS: $tcp_flags...\n";

    if (defined $synack_seq && $synack_seq) {
        if ($synack_seq == $syn_seq ) {
            print "[+] received ACK to our SYN...\n" ;
            $ack_seq = $synack_seq + 1;
            print "[+] packet details:\n";
	    print "\tin response to $syn_seq\n";
	    print "\tSEQ: $synack_seq\n";
	    print "\tACK: $synack_ack\n";
	    print "\tFLAGS: $tcp_flags\n";
        }
        else {
            print "[+] ignoring TCP packet from $ip->{src_ip}";
            print ":$tcp->{src_port} to $ip->{dest_ip}";
            print ":$tcp->{dest_port} flags $tcp->{flags}...\n";
        }
    }
    else {
        print "[*] ignoring packet from $ip->{src_ip} to ";
        print "$ip->{dest_ip}...\n";
    }   

}
