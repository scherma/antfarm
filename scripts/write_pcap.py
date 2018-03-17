#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import sys, os, stat

# write tcpdump.sh file
tcpdump = "/usr/local/unsafehex/{}/utils/tcpdump.sh".format(sys.argv[1])
with open(tcpdump, "w") as f:
    lines = [
        "#!/bin/bash\n",
        'D="$(date +%Y%m%d).pcap"\n',
        "tcpdump -i vneta -w /usr/local/unsafehex/{}/pcaps/$D\n".format(sys.argv[1])
    ]
    for line in lines:
        f.write(line)
        
st = os.stat(tcpdump)
os.chmod(tcpdump, st.st_mode | stat.S_IEXEC)

# write rotate file
rotate = "/usr/local/unsafehex/{}/utils/rotate.sh".format(sys.argv[1])
with open(rotate, "w") as f:
    lines = [
        "#!/bin/bash\n",
        "PID=$(pgrep -f tcpdump.sh)\n",
        "/bin/kill -9 $PID\n",
        "/usr/local/unsafehex/{}/utils/tcpdump.sh &>/dev/null &\n".format(sys.argv[1]),
        "find /usr/local/unsafehex/{}/pcaps -name *.pcap -mtime +7 -exec rm {}\;"
    ]
    for line in lines:
        f.write(line)
        
st = os.stat(rotate)
os.chmod(rotate, st.st_mode | stat.S_IEXEC)