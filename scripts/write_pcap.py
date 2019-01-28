#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import sys, os, stat

dumpcap = "/usr/local/unsafehex/{}/utils/dumpcap.sh".format(sys.argv[1])
with open(dumpcap, "w") as f:
    lines = """#!/bin/bash
STIME=`date -u +"\%s"`;
CURRENT_MINS=`date -u +"%M"`;
REMAINING_MINS=$((60 - $CURRENT_MINS));
CURRENT_MINUTE_SECS=`date -u +"%S"`;
REMAINING_SECS_IN_MINUTE=$((60 - $CURRENT_MINUTE_SECS));
REMAINING_MINS_IN_SECONDS=$(($REMAINING_MINS * 60));
REMAINING_SECS=$(($REMINAING_SECS_IN_MINUTE + $REMAINING_MINS_IN_SECONDS));

dumpcap -i virbr0 -a duration:$REMAINING_SECS -q -w /usr/local/unsafehex/{}/pcaps/$STIME.pcap";
""".format(sys.argv[1])
    f.write(lines)
    
st = os.stat(dumpcap)
os.chmod(dumpcap, st.st_mode | stat.S_IEXEC)
