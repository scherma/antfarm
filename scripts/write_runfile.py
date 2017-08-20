#!/usr/bin/env python
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import sys

content = """# © https://github.com/scherma
# contact http_error_418@unsafehex.com
param(
    [Parameter(Mandatory=$true)][string]$filename
)

$client = New-Object System.Net.WebClient
$client.DownloadFile("http://{0}:{1}/"+$filename, "C:\\Users\\James\\Downloads\\"+$filename)

cmd /c start C:\\Users\\James\\Downloads\\$filename""".format(sys.argv[1], sys.argv[2])

with open(sys.argv[3], 'w') as f:
	f.write(content)