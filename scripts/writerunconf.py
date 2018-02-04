#!/usr/bin/env python
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import configparser
import sys

# arguments: instancename dbpass

instancename = sys.argv[1]
dbpass = sys.argv[2]
gateway = sys.argv[3]
netmask = sys.argv[4]

conf = configparser.ConfigParser()

conf.add_section("General")

conf.set('General', 'instancename', instancename)
conf.set('General', 'dbname', instancename)
conf.set('General', 'dbuser', instancename)
conf.set('General', 'dbpass', dbpass)
conf.set('General', 'loglevel', 'DEBUG')
conf.set('General', 'runloglevel', 'INFO')
conf.set('General', 'mountdir', '/mnt/{0}'.format(instancename))
conf.set('General', 'basedir', '/usr/local/unsafehex/')
conf.set('General', 'logdir', '/usr/local/unsafehex/{0}/runmanager/logs'.format(instancename))
conf.set('General', 'suricata_log', '/var/log/suricata/eve.json')
conf.set('General', 'gateway_ip', gateway)
conf.set('General', 'netmask', netmask)

with open('/usr/local/unsafehex/{0}/runmanager/runmanager.conf'.format(instancename), 'w') as f:
    conf.write(f)
