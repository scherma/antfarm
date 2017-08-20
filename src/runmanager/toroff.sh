#!/bin/bash
service tor stop
iptables -t nat -D PREROUTING -i virbr0 -p tcp --syn -j REDIRECT --to-ports 8081 -s 192.168.43.0/24 ! --dport 8080
iptables -t nat -D PREROUTING -i virbr0 -p udp --dport 53 -j REDIRECT --to-ports 5353 -s 192.168.43.0/24
