#!/usr/bin/env python
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

from lxml import etree
import sys

gateway_ip = sys.argv[1]
netmask = sys.argv[2]
netfile = sys.argv[3]

root = etree.Element("network")
name = etree.SubElement(root, "name")
bridge = etree.SubElement(root, "bridge")
domain = etree.SubElement(root, "domain")
ip = etree.SubElement(root, "ip")
name.text = "vneta"
bridge.set("name", "virbr0")
bridge.set("stp", "on")
bridge.set("delay", "0")
domain.set("name", "vneta")
ip.set("address", gateway_ip)
ip.set("netmask", netmask)

with open(netfile, 'w') as f:
	f.write(etree.tostring(root, encoding="unicode", pretty_print=True))