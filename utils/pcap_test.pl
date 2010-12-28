#!/usr/bin/env perl

use warnings;
use strict;
use Net::RawIP;
use NetPacket::Ethernet;
use NetPacket::IP;
use Net::Pcap;

print "[+] device lookup... ";
my $err = '';
my $dev = Net::Pcap::pcap_lookupdev(\$err);  # find a device
my @dev = Net::Pcap::pcap_findalldevs(\$err);

if (defined $err && $err) {
    print "failed - $err !\n";
    exit 1;
}

else {
    print "found $dev...\n";
}


print "[+] opening live capture...\n";
# open the device for live listening
my $pcap = Net::Pcap::pcap_open_live($dev, 1024, 1, 0, \$err);

print "[+] listening for next 3 packets...\n";
# loop over next 10 packets
Net::Pcap::pcap_loop($pcap, 3, \&process_packet, "just for the demo");

print "[+] closing capture...\n";
# close the device
Net::Pcap::pcap_close($pcap);

exit 0;

sub process_packet {
    my ($user_data, $header, $packet) = @_;
    my $eth = NetPacket::Ethernet->decode($packet);
    my $ip  = NetPacket::IP->decode($eth->{data});

    my $src_ip  = $ip->{src_ip} ;
    my $dst_ip  = $ip->{dest_ip} ;
    my $proto   = $ip->{proto};


    print "[+] received IPv4 packet " .
          "src $src_ip dst $dst_ip proto $proto...\n";
}
