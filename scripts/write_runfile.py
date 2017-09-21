#!/usr/bin/env python
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import sys

content = """# © https://github.com/scherma
# contact http_error_418@unsafehex.com
param(
    [Parameter(Mandatory=$true)][string]$filename,
    [Parameter(Mandatory=$true)][string]$dldir
)

$client = New-Object System.Net.WebClient
$dlname = [uri]::EscapeDataString($filename)
$client.DownloadFile("http://{0}:{1}/$dldir/$dlname", "C:\\Users\\James\\Downloads\\$filename")

explorer.exe "C:\\Users\\James\\Downloads\\$filename" """.format(sys.argv[1], sys.argv[2])

with open(sys.argv[3], 'w') as f:
	f.write(content)