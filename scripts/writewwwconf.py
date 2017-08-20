#!/usr/bin/env python
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import json, sys
# arguments: instancename, dbpass
instancename = sys.argv[1]
dbpass = sys.argv[2]

displayname = instancename[0].upper() + instancename[1:]

conf = {
    "database": {
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

with open('/usr/local/unsafehex/{0}/www/{0}/lib/config.json'.format(instancename), 'w') as f:
    f.write(json.dumps(conf, indent=4, separators=(",", ": ")))
