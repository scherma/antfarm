#!/usr/bin/env python
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import json, sys
# arguments: instancename, dbpass
instancename = sys.argv[1]
dbpass = sys.argv[2]
gateway = sys.argv[3]
netmask = sys.argv[4]

displayname = instancename[0].upper() + instancename[1:]

conf = {
    "database": {
        "name": instancename,
        "username": instancename,
        "password": dbpass
    },
    
    "site": {
        "name": instancename,
        "displayName": displayname
    },
    
    "clamav": {
        "port": 9999
    },
    
    "network": {
        "gateway_ip": gateway,
        "netmask": netmask
    },
    
    "filters": {
        "subnets":  [
        ],
        "hostnames" :{
            "com": [
                "msftncsi",
                "windowsupdate",
                "microsoft",
                "symcd",
                "symcb",
                "verisign",
                "symantec",
                "bing",
                "identrust"
            ],
            "co.uk": [
                "hsbc"
            ]
        },
        "tlsnames": [
            "www.hsbc.co.uk",
            "www1.member-hsbc-group.com",
            "www.mcmprod.hsbc.co.uk",
            "www.askus.hsbc.co.uk",
            "*.tiqcdn.com",
            "*.demdex.net",
            "*.vo.msecnd.net"
        ]
    }
}

apiconf = {
    "database": {
        "username": instancename,
        "password": dbpass
    },
    
    "site": {
        "name": instancename,
        "displayName": displayname
    }
}

with open('/usr/local/unsafehex/{0}/www/lib/config.json'.format(instancename), 'w') as f:
    f.write(json.dumps(conf, indent=4, separators=(",", ": ")))

with open('/usr/local/unsafehex/{0}/api/lib/config.json'.format(instancename), 'w') as f:
    f.write(json.dumps(apiconf, indent=4, separators=(",", ": ")))