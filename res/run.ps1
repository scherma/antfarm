# © https://github.com/scherma
# contact http_error_418@unsafehex.com
param(
    [Parameter(Mandatory=$true)][string]$filename
)

$client = New-Object System.Net.WebClient
$client.DownloadFile("http://192.168.43.1:8080/"+$filename, "C:\Users\James\Downloads\"+$filename)

cmd /c start C:\Users\James\Downloads\$filename
