#!/usr/bin/env perl

###############################################################################
###################
# PACKAGE IMPORTS #
###################
use warnings;
use strict;
use Data::Dumper;
use Net::RawIP;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Time::localtime;

###############################################################################
#############
# CONSTANTS #
#############
# IP protos
use constant {
	PROTO_TCP	=> 0x00,
	PROTO_UDP	=> 0x01,
	PROTO_ICMP	=> 0x02,
};

# TCP FLAGS
use constant {
	TCP_FLAG_FIN	=> 0x01,
	TCP_FLAG_SYN	=> 0x02,
	TCP_FLAG_RST	=> 0x04,
	TCP_FLAG_PSH	=> 0x08,
	TCP_FLAG_ACK	=> 0x10,
	TCP_FLAG_URG	=> 0x20,
	
};

# PACKET VALUES
use constant {
	ISN		=> int(rand(2 ** 32)),
	PACKET_WINDOW	=> 16392,
};

# PCAP VALUES
use constant {
	SNAPLEN		=> 1600,
	PROMISC_MODE	=> 0,
	TIMEOUT		=> 0,
	USER_DATA	=> '',
	NOBLOCK		=> 1,
	OPTIMISE_FILTER => 0,
	CAPTURE_IF	=> 'eth0',
};


###############################################################################
################################
# GLOBAL VARIABLE DECLARATIONS #
################################
# TCP flags

# PACKET SETUP
my $src = $ARGV[0] or &usage();
my $sp	= $ARGV[1] or &usage();
my $dst = int(rand(2 ** 16 - 1024)) + 1024;
my $dp	= $ARGV[2] or &usage();


print "[+] getting packet capture descriptor...\n";
my $pcap = &capinit('tcp port 4141');

if (defined $pcap) {
	print "[+] valid capture filter descriptor...\n";
	capdie($pcap);
}
else {
	die "[!] cowardly refusing to blindly send packets!";
}

print "[+] building initial SYN packet...\n";
my @synpkt_params 	= ($sp, $dp, TCP_FLAG_SYN, 0, 0);
my $synpkt		= build_pkt($src, $dst, '', PROTO_TCP, @synpkt_params);
if (!defined $synpkt) {
	die "[!] error building initial SYN packet!";
}














###############################################################################
####################
# SUB DECLARATIONS #
####################

# usage - print a quick usage message and die()
sub usage( ) {
	die "usage: $0 <src> <src port> <dst> <dst port>\n";
}

#########################################################################
# TODO: put the capture subs in a separate package of capture utilities #
#########################################################################
# cap_setup - prepare a capture
#	parameters: capture filter string
#	returns: packet capture descriptor
sub capinit ( ) {
	package Net::Pcap ;
	my ($filter)	= @_ ;			# capture filter string
	
	print "[+] attempting to open capture descriptor";
	if (defined $filter) {
		print " with filter '$filter'"
	}
	print "...\n";
	
	my $compiled	= undef ;		# compiled capture filter
	my $err		= undef;		# error message buffer
	my $pcap 	= undef ;		# capture descriptor
	my $net		= undef ;		# device network
	my $netmask	= undef ;		# device netmask
	my $dev		= undef ;		# device to capture on

	if (defined &main::CAPTURE_IF) {
		print "[+] will use " . &main::CAPTURE_IF . " for capture...\n";	
		$dev	= &main::CAPTURE_IF ;
	}
	else {
		print "[+] looking up capture device... ";
		$dev	= lookupdev(\$err);	# capture device

		if (defined $err) {
			print "\n[!] error getting device: $err...\n";
			return undef;
		}
		else {
			print "found $dev...\n";
		}
	}

	print "[+] looking up $dev\'s network and netmask...\n";
	lookupnet($dev, \$net, \$netmask, \$err);
	if (defined $err) {
		print "[!] error looking up network: $err...\n";
		return undef;
	}

	print "[+] attempting to open live packet capture descriptor...\n";
	$pcap	= open_live($dev, &main::SNAPLEN, &main::PROMISC_MODE,
				 &main::TIMEOUT, \$err);
	
	if (!defined $pcap) {
		print "[!] error opening packet capture descriptor - $err !\n";
		return undef;
	}

	if (&main::NOBLOCK && defined &Net::Pcap::setnonblock) {
		print "[+] attempting to put capture descriptor in nonblocking";
		print "mode...\n";
		setnonblock($pcap, &main::NOBLOCK, \$err);
		if (defined $err) {
			print "[!] error setting capture descriptor to ";
			print "nonblocking mode"
		}
	}

	print "[+] compiling capture filter...\n";
	$err = compile($pcap, \$compiled, $filter, &main::OPTIMISE_FILTER,
			    $netmask);
	
	if ($err == -1) {
		print "[!] error compiling capture filter!\n";
	}

	print "[+] successfully set up packet capture descriptor!\n";
	return $pcap
}

# capdie - close the capture descriptor
sub capdie {
	my ($pcap) = @_ ;
	&Net::Pcap::close($pcap);
}


##################
# packet sending #
##################
# fire - send a packet
#	arguments: appropriate arguments for build_pkt or a prebuilt packet
sub fire {
	print "[+] received command to fire!\n";
	my ($build, @process)	= @_ ;
	
	my $pkt 		= undef ;		# packet to send
	my ($delay, $count)	= 0;			# delay before sending,
							# number of packets to
							# send
	
	if ($build) {
		my ($delay, $count, $pkt) = @process;
		print "[+] using prebuilt packet...\n";
		($pkt) = @_ ;
	}
	else {
		my ($delay, $count, @build_data) = @process;
		print "[+] building packet...\n";
		$pkt = &build_pkt(@build_data);
	}
	
	print "[+] sending...\t";
	$pkt->send($delay, $count);
	print "sent!\n";
}


########################
# packet building subs #
########################

# build_pkt - IP packet building front end
#	arguments: $src_ip, $dst_ip, $packet_data, $proto, @protohdr
#	returns: a Net::RawIP packet with the appropriate IP header.
#		 if $proto matches one of the constants, the appropriate
#		 proto-specific packet builder is called.
#		 note that Net::RawIP defaults to TCP if no other proto is
#		 spec'd. accordingly, PROTO_TCP defaults to 0.
sub build_pkt {
	my ($src_ip, $dst_ip, $packet_data, $proto, @protohdr)	= @_ ;
	my $ipid	= int(rand(2 ** 16));		# IPID
	my $pkt		= undef ;
	
	if ($proto == PROTO_TCP) {
		$pkt = &build_pkt_tcp($src_ip, $dst_ip, $ipid, $packet_data,
				      @protohdr);
	}
	elsif ($proto == PROTO_UDP) {
		$pkt = &build_pkt_udp();
	}
	elsif ($proto == PROTO_ICMP) {
		# not implemented yet
	}
	else {
		# FAIL
	}
	
	return $pkt;
	
}

sub build_pkt_tcp {
	# note - ackseq is the TCP SEQ of the last packet sent by the other end
	# this will get set to $ackseq++ later on.
	# pnum is the packet number, i.e. offset from ISN
	# protohdr should be:
	# $src_port, $dst_port, $flags, $pnum, $ackseq
	my ($src_ip, $dst_ip, $ipid, $packet_data, $src_port,
	    $dst_port, $flags, $pnum, $ackseq) = @_ ;
	
	my ($fin, $syn, $rst, $psh, $ack, $urg) = 0;
	if ($flags & TCP_FLAG_FIN) { $fin = 1; }
	if ($flags & TCP_FLAG_SYN) { $syn = 1; }
	if ($flags & TCP_FLAG_RST) { $rst = 1; }
	if ($flags & TCP_FLAG_PSH) { $psh = 1; }
	if ($flags & TCP_FLAG_ACK) { $ack = 1; }
	if ($flags & TCP_FLAG_URG) { $urg = 1; }
	
	
	my $pkt = Net::RawIP->new({
		ip => {
			saddr	=> $src_ip,
			daddr	=> $dst_ip,
			id	=> $ipid,
		},
		tcp => {
			source	=> $src_port,
			dest	=> $dst_port,
			seq	=> ISN + $pnum,
			ack_seq	=> $ackseq,
			urg	=> $urg,
			ack	=> $ack,
			psh	=> $psh,
			rst	=> $rst,
			syn	=> $syn,
			fin	=> $fin,
			window	=> PACKET_WINDOW,
			data	=> $packet_data,
		},
	});
	
	return $pkt;
}

sub build_pkt_udp {
	my ($src_ip, $dst_ip, $ipid, $src_port, $data, $dst_port) = @_ ;
	
	my $pkt = Net::RawIP->new({
		ip => {
			src	=> $src_ip,
			dest	=> $dst_ip,
			id	=> $ipid,
		},
		udp => {
			source	=> $src_port,
			dest	=> $dst_port,
			data	=> $data,
		},
	});
	
	return $pkt ;
}
