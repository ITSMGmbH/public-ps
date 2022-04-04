$NowString = get-date -Format "MMddyyyy-HHmmss"
$DiagLogName = $env:USERPROFILE + "\Desktop\ITSM-SupportInfoLog-$env:computername-$NowString.txt"

Write-Host "Please Wait..."
quser | out-file -Append -FilePath $DiagLogName 
ipconfig /all | out-file -Append -FilePath $DiagLogName 
route print | out-file -Append -FilePath $DiagLogName 
$NetIPConfiguration = Get-NetIPConfiguration

$dnsservers = ($NetIPConfiguration | Select-Object -ExpandProperty DNSServer).ServerAddresses | select -Unique
foreach ($dnsserver in $dnsservers) {
    Write-Host "." -NoNewline
    Test-NetConnection $dnsserver | fl | out-file -Append -FilePath $DiagLogName 
    Resolve-DnsName -Name vpn.itsm.de -Server $address | out-file -Append -FilePath $DiagLogName 
}

$Gateways = ($NetIPConfiguration | select -ExpandProperty IPV4DefaultGateway).NextHop
foreach($Gateway in $Gateways)
{
    Write-Host "." -NoNewline
    Test-NetConnection $Gateway | fl | out-file -Append -FilePath $DiagLogName 
}

Write-Host "." -NoNewline
Test-NetConnection vpn.itsm.de -Port 443  | fl | out-file -Append -FilePath $DiagLogName
Write-Host "." -NoNewline
Test-NetConnection vpn.itsm.de -TraceRoute | fl | out-file -Append -FilePath $DiagLogName 
Write-Host "." -NoNewline
Test-NetConnection google.de -Port 443 | fl | out-file -Append -FilePath $DiagLogName 
Write-Host "." -NoNewline
Test-NetConnection google.de -TraceRoute | fl | out-file -Append -FilePath $DiagLogName 
Write-Host "."
Test-NetConnection 8.8.8.8 -TraceRoute | fl | out-file -Append -FilePath $DiagLogName 

Write-Host "."
Write-Host "Public IP:" | out-file -Append -FilePath $DiagLogName 
((Invoke-WebRequest 'https://api.myip.com/').content | ConvertFrom-Json).ip | out-file -Append -FilePath $DiagLogName 

systeminfo | out-file -Append -FilePath $DiagLogName 

Write-Host "Finished. Log written to $DiagLogName"