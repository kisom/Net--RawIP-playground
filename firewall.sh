TARGET=0.0.0.0

sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST  \
    -d ${TARGET} --dport 5932 -j DROP
sudo iptables -A OUTPUT -d ${TARGET} -p ICMP \
    --icmp-type port-unreachable -j DROP

