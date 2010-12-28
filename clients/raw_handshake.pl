#!/usr/bin/env perl

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


#############
# CONSTANTS #
#############
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
};


################################
# GLOBAL VARIABLE DECLARATIONS #
################################
# TCP flags

# PACKET SETUP
#my $src = $ARGV[0] or &usage();
#my $dst = $ARGV[1] or &usage();

my $pcap = &capinit('tcp port 4141');

if (defined $pcap) {
	print "valid capture filter descriptor...\n";
	capdie($pcap);
}


####################
# SUB DECLARATIONS #
####################

# usage - print a quick usage message and die()
sub usage( ) {
	die "usage: $0 <src> <dst>\n";
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

	print "[+] looking up capture device... ";
	my $dev		= lookupdev(\$err);# capture device	

	if (defined $err) {
		print "\n[!] error getting device: $err...\n";
		return undef;
	}
	else {
		print "found $dev...\n";
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
