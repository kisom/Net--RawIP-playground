#!/usr/bin/env perl
# set up a simple listener that prints clients that connect and prints the
# client's payload.
# usage: $0 <addr> <port>
# also permissible: $0 <port> in which case the server will bind to localhost


use warnings;
use strict;
use IO::Socket;
use Socket;

my $PORT = 4141;
my $ADDR = 127.0.0.1;

print "[+] starting TCP server...";

if (@ARGV) {
    if (@ARGV > 0) {
        if (@ARGV == 1) {
            $PORT = int($ARGV[0])
        }
        elsif (@ARGV == 2) {
            $ADDR = $ARGV[0];
            $PORT = int($ARGV[1]);
        }    
    }
}

print "saddr: $ADDR\n";
#if ($ADDR =~ /(\d{1,3]}[.]}){3}\d{1,3}/) {
#    $ADDR = gethostbyaddr($ADDR, AF_INET);
#}

print "[+] attemtping to bind a socket to $ADDR:$PORT\n";
my $server  = IO::Socket::INET->new(LocalPort => $PORT,
                                    LocalAddr => $ADDR,
                                    Type      => SOCK_STREAM,
                                    Reuse     => 1,
                                    Listen    => 10 )
            or die "couldn't set up TCP server on port $PORT : $@\n";

my ($addr, $port) = &get_ap($server);

print "[+] listening on $addr:$port...\n";
while (my ($client, $client_addr) = $server->accept()) {
    my ($port, $packed_ip) = sockaddr_in($client_addr);
    my $dq = inet_ntoa($packed_ip);
    my $data = "";
    $client->recv($data, 1024);
    
    print "[+] connection from $dq:$port with data: $data\n";
}

print "[+] shutting down server...\n";
$server->close();

print "[+] finished!\n";
exit 0;

sub get_ap() {
    my $socket = shift(@_);
    my $sockaddr = getsockname($socket);
    my ($port, $addr) = sockaddr_in($sockaddr);
    $addr = inet_ntoa( $addr );
    return ($addr, $port);
}