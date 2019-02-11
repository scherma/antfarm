#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import pyshark, json, sys, arrow

def conversation_starter(pkt):
	try:
		d = {}
		protocol = pkt.transport_layer
		src_addr = pkt.ip.src
		src_port = pkt[pkt.transport_layer].srcport
		dst_addr = pkt.ip.dst
		dst_port = pkt[pkt.transport_layer].dstport
		if protocol == "TCP":
			str_flags = (pkt["TCP"].flags)
			str_flags = str_flags[-4:]
			int_flags = int(str_flags)
			# this try/except is magic: if it is present, no exception is thrown
			# if not, the bitwise operation triggers a TypeError

			if int_flags == 2: # syn flag set, ack not set
				d["timestamp"] = pkt.sniff_timestamp
				d["protocol"] = protocol
				d["src"] = src_addr
				d["dst"] = dst_addr
				d["srcport"] = src_port
				d["dstport"] = dst_port
			
		else:
			d["timestamp"] = pkt.sniff_timestamp
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
			
	cap.close()		
	return c

def main():
	pcapfile = sys.argv[1]
	print(json.dumps(conversations(pcapfile), indent=2, separators=(",", ": ")))
	
if __name__ == '__main__':
	main()