#!/usr/bin/env perl

use warnings;
use strict;
use IO::Socket;

my $PORT    = 4141;
my $ADDR    = $ARGV[0] or &usage();
my $DATA    = $ARGV[1];

if (!$DATA) {
    $DATA = "HIHI";
}

print "[+] setting up socket...\n";
my $client  = IO::Socket::INET->new(
                                    PeerAddr => $ADDR,
                                    PeerPort => $PORT,
                                    Proto    => 'tcp',
                                    Type     => SOCK_STREAM
            ) or die "couldn't connect to $ADDR:$PORT - $@\n";
            
print "[+] sending " . length($DATA) . " bytes of data...\n";
$client -> send($DATA, 0);
print "[+] closing socket...\n";
$client -> close();
print "[+] finished!\n";
exit 0;

sub usage( ) {
	die "usage: $0 <dst> [data]\n\tdata will be 'HIHI' if no data " .
	    "is specified.\n";
}

