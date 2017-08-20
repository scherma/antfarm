#!/usr/bin/env python
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import sys, ipaddress, os

addr = sys.argv[1]
netmask = sys.argv[2]
writedir = sys.argv[3]

insert = ipaddress.IPv4Network(u"{0}/{1}".format(addr, netmask), strict=False).exploded

toron_txt = """#!/bin/bash
service tor start
iptables -t nat -I PREROUTING 1 -i virbr0 -p tcp --syn -j REDIRECT --to-ports 8081 -s {0} ! --dport 8080
iptables -t nat -I PREROUTING 1 -i virbr0 -p udp --dport 53 -j REDIRECT --to-ports 5353 -s {0}""".format(insert)

toroff_txt = """#!/bin/bash
service tor stop
iptables -t nat -D PREROUTING -i virbr0 -p tcp --syn -j REDIRECT --to-ports 8081 -s {0} ! --dport 8080
iptables -t nat -D PREROUTING -i virbr0 -p udp --dport 53 -j REDIRECT --to-ports 5353 -s {0}""".format(insert)

with open(os.path.join(writedir, "toron.sh"), 'w') as f:
	f.write(toron_txt)
	
with open(os.path.join(writedir, "toroff.sh"), 'w') as f:
	f.write(toroff_txt)