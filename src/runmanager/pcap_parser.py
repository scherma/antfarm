#!/usr/bin/env python
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import pyshark, json, sys

def conversation_starter(pkt):
	try:
		d = {}
		protocol = pkt.transport_layer
		src_addr = pkt.ip.src
		src_port = pkt[pkt.transport_layer].srcport
		dst_addr = pkt.ip.dst
		dst_port = pkt[pkt.transport_layer].dstport
		if protocol == "TCP":
			if int(pkt["TCP"].flags) & 2 and not int(pkt["TCP"].flags) & 16: # syn flag set, ack not set
				d["protocol"] = protocol
				d["src"] = src_addr
				d["dst"] = dst_addr
				d["srcport"] = src_port
				d["dstport"] = dst_port
				return d
		else:
			d["protocol"] = protocol
			d["src"] = src_addr
			d["dst"] = dst_addr
			d["srcport"] = src_port
			d["dstport"] = dst_port
			return d
	except AttributeError as e:
		pass

def conversations(pcapfile):
	c = []
	cap = pyshark.FileCapture(pcapfile)
	for pkt in cap:
		d = conversation_starter(pkt)
		if d:
			c.append(d)
			
	return c

def main():
	pcapfile = sys.argv[1]
	with open('pcap_summary.json', 'w') as f:
		f.write(json.dumps(conversations(pcapfile)))
	
if __name__ == '__main__':
	main()