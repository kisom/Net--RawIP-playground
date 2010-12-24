#!/usr/bin/env perl

use warnings;
use strict;
use IO::Socket;
use Socket;

my $PORT = 4141;

print "[+] starting TCP server...";

if (@ARGV) {
    $PORT = int($ARGV[0]);
}

print "[+] binding socket to port $PORT\n";
my $server  = IO::Socket::INET->new(LocalPort => $PORT,
                                    Type      => SOCK_STREAM,
                                    Reuse     => 1,
                                    Listen    => 10 )
            or die "couldn't set up TCP server on port $PORT : $@\n";

while (my ($client, $client_addr) = $server->accept()) {
    my ($port, $packed_ip) = sockaddr_in($client_addr);
    my $dq = inet_ntoa($packed_ip);
    my $data = "";
    $client->recv($data, 1024);
    
    print "[+] connection from $dq:$port with data: $data\n";
}


