#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import configparser
import sys

# arguments: instancename dbpass

instancename = sys.argv[1]
user = sys.argv[2]

conf = configparser.ConfigParser()
conf.optionxform = str

conf.add_section("Unit")

conf.set('Unit', 'Description', '{} management service'.format(instancename))
conf.set('Unit', 'After', 'libvirtd-guests.service')
conf.set('Unit', 'Documentation', 'https://github.com/scherma/antfarm')

conf.add_section("Service")

conf.set('Service', 'Type', "simple")
conf.set('Service', 'EnvironmentFile', '/usr/local/unsafehex/{}/runmanager/runmanager.env'.format(instancename))
conf.set('Service', 'User', user)
conf.set('Service', 'Group', instancename)
conf.set('Service', 'ExecStart', '/usr/local/unsafehex/{0}/runmanager/runmanager /usr/local/unsafehex/{0}/runmanager/runmanager.conf'.format(instancename))
conf.set('Service', 'ExecReload', '/bin/kill -HUP $MAINPID')
conf.set('Service', 'KillMode', 'process')
conf.set('Service', 'Restart', 'on-failure')

conf.add_section("Install")

conf.set('Install', 'WantedBy', 'multi-user.target')

with open('/etc/systemd/system/{}.service'.format(instancename), 'w') as f:
    conf.write(f)
    
pcapconf = configparser.ConfigParser()
pcapconf.optionxform = str

pcapconf.add_section("Unit")

pcapconf.set("Unit", "Description", "{} pcap service".format(instancename))
pcapconf.set("Unit", "After", "network.target")

pcapconf.add_section("Service")

pcapconf.set("Service", "Type", "simple")
pcapconf.set('Service', 'User', user)
pcapconf.set("Service", "ExecStart", "/usr/bin/tshark -n -i vneta -b duration:3600 -b files:24 -w /usr/local/unsafehex/{}/pcaps/ring.pcap".format(instancename))

pcapconf.add_section("Install")

pcapconf.set("Install", "WantedBy", "multi-user.target")

with open("/etc/systemd/system/pcapring.service", "w") as f:
    conf.write(f)
    

