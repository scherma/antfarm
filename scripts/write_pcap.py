#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import sys, os, stat

dumpcap = "/usr/local/unsafehex/{}/utils/dumpcap.sh".format(sys.argv[1])
with open(dumpcap, "w") as f:
    lines = """#!/bin/bash
HOUR=`date -u +"%H"`;
dumpcap -i vneta -a duration:3600 -q -w /usr/local/unsafehex/{}/pcaps/$HOUR.pcap""".format(sys.argv[1])
    f.write(lines)
    
st = os.stat(dumpcap)
os.chmod(dumpcap, st.st_mode | stat.S_IEXEC)
