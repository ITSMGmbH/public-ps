#########
# Autor: (c) Marco.Hahnen@ITSM.de
# Zweck: Collect Support Infos
# Version: 1.0
# Read: https://docs.itsm.de/display/~hahnenmarco/Get+ITSM+Support+Info
# Prerequisites:
# - nothing
# ChangeLog
# - 1.0 first release
# ToDo
# - nothing
########## 
Clear-Host
$NowString = get-date -Format "MMddyyyy-HHmmss"
$DiagLogName = $env:USERPROFILE + "\Desktop\ITSM-SupportInfoLog-$env:computername-$NowString.txt"
Start-Transcript -Path $DiagLogName 

function Get-Connectivity {
    param (
        $Target,
        $Type = "icmp",
        $Port
    )
    if($type -eq "icmp")
    {
        Write-Host "Pinging $Target..." -BackgroundColor Cyan -ForegroundColor black 
        $test = Test-NetConnection $Target
        if($test.PingSucceeded -eq "True") { 
            Write-Host "Ping $Target succeeded" -BackgroundColor Green -ForegroundColor black 
        }
        else {
            Write-Host "Ping $Target failed" -BackgroundColor Red -ForegroundColor White
        }
    }
    elseif($type -eq "tcp") {
        Write-Host "TcpTest $Target TCP Port $Port..." -BackgroundColor Cyan -ForegroundColor black 
        $test = Test-NetConnection $Target -Port $Port 
        if($test.TcpTestSucceeded -eq "True") { 
            Write-Host "TcpTest $Target $Port succeeded" -BackgroundColor Green -ForegroundColor black 
        }
        else {
            Write-Host "TcpTest $Target $Port failed" -BackgroundColor Red -ForegroundColor White
        }
    }
    elseif($type -eq "traceroute") {
        Write-Host "Traceroute $Target..." -BackgroundColor Cyan -ForegroundColor black 
        $test = Test-NetConnection $Target -TraceRoute
        if($test.PingSucceeded -eq "True") { 
            Write-Host "TraceRoute $Target $Port succeeded" -BackgroundColor Green -ForegroundColor black 
        }
        else {
            Write-Host "TraceRoute $Target $Port failed" -BackgroundColor Red -ForegroundColor White
        }
    }
    else {
        throw "Type not specified"
    }
    $test | Format-List
}

function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

Write-Host "Please Wait..."

Write-Host "`nCheck Adminrole" -BackgroundColor Cyan -ForegroundColor black 
if(Test-Administrator)
{
    write-host "User is admin" -BackgroundColor Green -ForegroundColor black 
}
else
{
    write-host "User is not admin" -BackgroundColor Red -ForegroundColor White
}

Write-Host "`nSysteminfo" -BackgroundColor Cyan -ForegroundColor black 
systeminfo

Write-Host "`nLogged on Users" -BackgroundColor Cyan -ForegroundColor black 
quser

Write-Host "`nRunning Processes" -BackgroundColor Cyan -ForegroundColor black 
if(Test-Administrator)
{
    Get-Process -IncludeUserName 
}
else
{
    Get-Process
}

Write-Host "`nServices" -BackgroundColor Cyan -ForegroundColor black 
Get-Service | ft

Write-Host "`nIPConfig" -BackgroundColor Cyan -ForegroundColor black 
ipconfig /all

Write-Host "`nRouting" -BackgroundColor Cyan -ForegroundColor black 
route print

Write-Host "`nConnectivity Tests" -BackgroundColor Cyan -ForegroundColor black 
$NetIPConfiguration = Get-NetIPConfiguration | Where-Object { $_.InterfaceDescription -notlike "*Hyper-V*" }

$dnsservers = ($NetIPConfiguration | Select-Object -ExpandProperty DNSServer | ? AddressFamily -eq "2").ServerAddresses | select -Unique
foreach ($dnsserver in $dnsservers) {
    Get-Connectivity -Target $dnsserver
    
    Write-Host "Test DNS Server $dnsserver resolve vpn.itsm.de" -BackgroundColor Cyan -ForegroundColor black 
    Resolve-DnsName -Name vpn.itsm.de -Server $dnsserver 
}

$Gateways = ($NetIPConfiguration | select -ExpandProperty IPV4DefaultGateway).NextHop
foreach($Gateway in $Gateways)
{
    Get-Connectivity -Target $Gateway
}

Get-Connectivity -Target vpn.itsm.de -type tcp -Port 443
Get-Connectivity -Target vpn.itsm.de -type traceroute
Get-Connectivity -Target google.de -type tcp -Port 443
Get-Connectivity -Target google.de -type traceroute
Get-Connectivity -Target 8.8.8.8 -type traceroute

Write-Host "`nPublic IP" -BackgroundColor Cyan -ForegroundColor black 
((Invoke-WebRequest 'https://api.myip.com/').content | ConvertFrom-Json).ip

Write-Host "`nSpeedTest" -BackgroundColor Cyan -ForegroundColor black 

#100M Testfile
$size = "100"
$in = "http://speedtest.frankfurt.linode.com/garbage.php?r=0.29286396544417626&ckSize=" + $size
$out = $env:temp +"\speedtest.bin"
$wc = New-Object System.Net.WebClient; "{0:N2} Mbit/sec" -f ((100/(Measure-Command {$wc.Downloadfile($in,$out)}).TotalSeconds)*8); del $out

Write-Host "`nFinished. Log written to $DiagLogName" -BackgroundColor Cyan -ForegroundColor black 