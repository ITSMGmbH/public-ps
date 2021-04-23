$NowString = get-date -Format "MMddyyyy-HHmmss"
$DiagLogName = $env:USERPROFILE + "\Desktop\ITSM-SupportInfoLog-$env:computername-$NowString.txt"
$WarningPreference = "SilentlyContinue"

Write-Host "Please Wait..."
Write-Host "." -NoNewline
quser | out-file -Append -FilePath $DiagLogName 
Write-Host "." -NoNewline
ipconfig /all | out-file -Append -FilePath $DiagLogName 
Write-Host "." -NoNewline
route print | out-file -Append -FilePath $DiagLogName 
Write-Host "." -NoNewline
$NetIPConfiguration = Get-NetIPConfiguration
Write-Host "." -NoNewline
$dnsservers = ($NetIPConfiguration | Select-Object -ExpandProperty DNSServer).ServerAddresses | select -Unique
foreach ($dnsserver in $dnsservers) {
    Write-Host "." -NoNewline
    Test-NetConnection $dnsserver | fl | out-file -Append -FilePath $DiagLogName 
    Resolve-DnsName -Name vpn.itsm.de -Server $address | out-file -Append -FilePath $DiagLogName 
}
Write-Host "." -NoNewline
$Gateways = ($NetIPConfiguration | select -ExpandProperty IPV4DefaultGateway).NextHop
Write-Host "." -NoNewline
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
Write-Host "." -NoNewline
Test-NetConnection 8.8.8.8 -TraceRoute | fl | out-file -Append -FilePath $DiagLogName 
Write-Host "." -NoNewline
systeminfo | out-file -Append -FilePath $DiagLogName 
Write-Host "Finished"