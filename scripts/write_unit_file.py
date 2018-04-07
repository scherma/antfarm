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

conf = configparser.ConfigParser()
conf.optionxform = str

conf.add_section("Unit")

conf.set("Unit", "Description", "{} user interface".format(instancename))
conf.set("Unit", "After", "nginx.service")

conf.add_section("Service")
conf.set("Service", "Type", "simple")
conf.set("Service", "User", user)
conf.set("Service", "WorkingDirectory", "/usr/local/unsafehex/{}/www".format(instancename))
conf.set("Service", "ExecStart", "/usr/local/bin/nodemon bin/www".format(instancename))

conf.add_section("Install")
conf.set("Install", "WantedBy", "multi-user.target")

with open("/etc/systemd/system/{}-ui.service".format(instancename), "w") as f:
    conf.write(f)
    
conf = configparser.ConfigParser()
conf.optionxform = str

conf.add_section("Unit")

conf.set("Unit", "Description", "{} user interface".format(instancename))
conf.set("Unit", "After", "nginx.service")

conf.add_section("Service")
conf.set("Service", "Type", "simple")
conf.set("Service", "User", user)
conf.set("Service", "WorkingDirectory", "/usr/local/unsafehex/{}/api".format(instancename))
conf.set("Service", "ExecStart", "/usr/local/bin/nodemon bin/www".format(instancename))

conf.add_section("Install")
conf.set("Install", "WantedBy", "multi-user.target")

with open("/etc/systemd/system/{}-api.service".format(instancename), "w") as f:
    conf.write(f)