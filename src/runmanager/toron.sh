#!/bin/bash
service tor start
iptables -t nat -I PREROUTING 1 -i virbr0 -p tcp --syn -j REDIRECT --to-ports 8081 -s 192.168.43.0/24 ! --dport 8080
iptables -t nat -I PREROUTING 1 -i virbr0 -p udp --dport 53 -j REDIRECT --to-ports 5353 -s 192.168.43.0/24
