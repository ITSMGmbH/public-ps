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

$logLevel = 2

# Verbose 	    5
# Informational 4
# Warning 	    3
# Error 	    2
# Critical 	    1
# LogAlways 	0

$NowString = get-date -Format "MMddyyyy-HHmmss"
$DiagLogFolder = "$env:USERPROFILE\Desktop\ITSM-SupportInfoLog"
$DiagLogName = "$DiagLogFolder\$env:computername-$NowString.txt"

Stop-Transcript -ErrorAction SilentlyContinue
Start-Transcript -Path $DiagLogName

$css = (Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/ITSMGmbH/public-ps/main/Get-ITSMSupportInfo.css").content
$js = (Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/ITSMGmbH/public-ps/main/Get-ITSMSupportInfo.js").content

$htmlHead = "
<html>
<head>
<style>
$css
</style>
<title>Report</title>
</head><body>"

$htmlEnd = "
<script>
$js
</script
</body>
</html>"

$htmlFolder= "$DiagLogFolder\html"

$connectivitySummerys= @()

$generalSummery = New-Object -TypeName psobject 
Add-Member -InputObject $generalSummery -MemberType NoteProperty -Name hostname -Value $null
Add-Member -InputObject $generalSummery -MemberType NoteProperty -Name isAdmin -Value $null
Add-Member -InputObject $generalSummery -MemberType NoteProperty -Name Uptime -Value $null
Add-Member -InputObject $generalSummery -MemberType NoteProperty -Name lastBootTime -Value $null
#Add-Member -InputObject $generalSummery -MemberType NoteProperty -Name loggedOnUsers -Value $null

if( !(Test-Path $DiagLogFolder) ) {
    New-Item -ItemType Directory $DiagLogFolder
}

if( !(Test-Path $htmlFolder) ) {
    New-Item -ItemType Directory $htmlFolder
}

$htmlFilePath = "$htmlFolder\report.html"
$htmlHead | Out-File -LiteralPath $htmlFilePath -Force

function Get-Connectivity {
    param (
        $Target,
        $Type = "icmp",
        $Port,
        $Note = "n/a"
    )
    $status = ""

    switch ($type) {
        "icmp" { 
            Write-Host "Pinging $Target..." -BackgroundColor Cyan -ForegroundColor black 
            $test = Test-NetConnection $Target
            if($test.PingSucceeded -eq "True") { 
                Write-Host "Ping $Target succeeded" -BackgroundColor Green -ForegroundColor black 
                $status = "success"
            }
            else {
                Write-Host "Ping $Target failed" -BackgroundColor Red -ForegroundColor White
                $status = "failed"
            }

            break
        }
        "tcp" {
            Write-Host "TcpTest $Target TCP Port $Port..." -BackgroundColor Cyan -ForegroundColor black 
            $test = Test-NetConnection $Target -Port $Port 
            if($test.TcpTestSucceeded -eq "True") { 
                Write-Host "TcpTest $Target $Port succeeded" -BackgroundColor Green -ForegroundColor black 
                $status = "success"
            }
            else {
                Write-Host "TcpTest $Target $Port failed" -BackgroundColor Red -ForegroundColor White
                $status = "failed"
            }

            break
        }
        "traceroute" {
            Write-Host "Traceroute $Target..." -BackgroundColor Cyan -ForegroundColor black 
            $test = Test-NetConnection $Target -TraceRoute
            if($test.PingSucceeded -eq "True") { 
                Write-Host "TraceRoute $Target $Port succeeded" -BackgroundColor Green -ForegroundColor black 
                $status = "success"
            }
            else {
                Write-Host "TraceRoute $Target $Port failed" -BackgroundColor Red -ForegroundColor White
                $status = "failed"
            }

            break
        }
        Default {
            throw "Type not specified"
        }
    }
    
    Write-Host $test | Format-List

    $connectivitySummery = New-Object -TypeName psobject 

    Add-Member -InputObject $connectivitySummery -MemberType NoteProperty -Name Target -Value $Target
    Add-Member -InputObject $connectivitySummery -MemberType NoteProperty -Name Type -Value $Type
    Add-Member -InputObject $connectivitySummery -MemberType NoteProperty -Name Status -Value $status
    Add-Member -InputObject $connectivitySummery -MemberType NoteProperty -Name Note -Value $Note


    return $connectivitySummery
}
function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function HtmlHeading {
    param (
        $text,
        $size="3"
    )
    $htmlText = "<h$size>$text</h$size>"
    return $htmlText
}

function AppendReport {
    param (
        $content,
        [switch]$raw,
        [switch]$collapsible,
        $collapsibleTitle = "Expand"
    )

    if($collapsible) {
        $html = "<button type=`"button`" class=`"collapsible`">$collapsibleTitle</button>
        <div class=`"content`">"
        $html | Out-File $htmlFilePath -Append
    }

    if($raw) {
        $content | Out-File $htmlFilePath -Append
    }else {
        $content | ConvertTo-Html -Fragment | Out-File $htmlFilePath -Append
    }

    if($collapsible) {
        "</div>" | Out-File $htmlFilePath -Append
    }
    
}

Write-Host "Please Wait..."

Write-Host "`nCheck Adminrole" -BackgroundColor Cyan -ForegroundColor black 
if(Test-Administrator)
{
    write-host "User is admin" -BackgroundColor Green -ForegroundColor black 
    $generalSummery.isAdmin = $true
}
else
{
    write-host "User is not admin" -BackgroundColor Red -ForegroundColor White
    $generalSummery.isAdmin = $false
}

Write-Host "`nSysteminfo" -BackgroundColor Cyan -ForegroundColor black 
systeminfo

$systeminfo = Get-ComputerInfo

$uptime = $systeminfo.OsUptime.toString()
$utHours = $uptime.Split('.')[0]
$utMinutes = $uptime.Split('.')[1].Split(':')[0]
$generalSummery.Uptime = "$utHours h, $utMinutes min"
$generalSummery.lastBootTime = $systeminfo.OsLastBootUpTime
$generalSummery.hostname = $systeminfo.CsCaption



Write-Host "`nLogged on Users" -BackgroundColor Cyan -ForegroundColor black 
quser

# $quserstring = ""
# foreach ($line in quser) {
#     $quserstring += "$line`n"
# }

# $generalSummery.loggedOnUsers = $quserstring

AppendReport -content (HtmlHeading -text "General info") -raw
AppendReport -content $generalSummery

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

AppendReport -content (HtmlHeading -text "Services") -raw
AppendReport -content (Get-Service | Select-Object DisplayName, ServiceName, Status, StartType) -collapsible

AppendReport -content (HtmlHeading -text "Stopped Auto Services") -raw
AppendReport -content (Get-Service | Where-Object {$_.StartType -like "*auto*" -and $_.Status -like "*stop*" } | Select-Object DisplayName, ServiceName, Status, StartType)

Write-Host "`nIPConfig" -BackgroundColor Cyan -ForegroundColor black 
ipconfig /all



Write-Host "`nRouting" -BackgroundColor Cyan -ForegroundColor black 
route print

Write-Host "`nConnectivity Tests" -BackgroundColor Cyan -ForegroundColor black 
$NetIPConfiguration = Get-NetIPConfiguration | Where-Object { $_.InterfaceDescription -notlike "*Hyper-V*" }

$dnsservers = ($NetIPConfiguration | Select-Object -ExpandProperty DNSServer | ? AddressFamily -eq "2").ServerAddresses | select -Unique
foreach ($dnsserver in $dnsservers) {

    $connectivitySummerys += (Get-Connectivity -Target $dnsserver -Note "Local Resolver")
    
    Write-Host "Test DNS Server $dnsserver resolve vpn.itsm.de" -BackgroundColor Cyan -ForegroundColor black 
    Resolve-DnsName -Name vpn.itsm.de -Server $dnsserver 
}

$Gateways = ($NetIPConfiguration | select -ExpandProperty IPV4DefaultGateway).NextHop
foreach($Gateway in $Gateways)
{
    $connectivitySummerys += (Get-Connectivity -Target $Gateway -Note "Gateway")
}

$connectivitySummerys += (Get-Connectivity -Target vpn.itsm.de -type tcp -Port 443 -Note "General Connectivity")
$connectivitySummerys += (Get-Connectivity -Target vpn.itsm.de -type traceroute -Note "General Connectivity")
$connectivitySummerys += (Get-Connectivity -Target google.de -type tcp -Port 443 -Note "General Connectivity")
$connectivitySummerys += (Get-Connectivity -Target google.de -type traceroute -Note "General Connectivity")
$connectivitySummerys += (Get-Connectivity -Target 8.8.8.8 -type traceroute -Note "General Connectivity")

AppendReport -content (HtmlHeading -text "Successfull Connectivity")  -raw
AppendReport -content ($connectivitySummerys | Where-Object {$_.Status -eq "success"})
AppendReport -content (HtmlHeading -text "Failed Connectivity")  -raw
AppendReport -content ($connectivitySummerys | Where-Object {$_.Status -eq "failed"})

Write-Host "`nPublic IP" -BackgroundColor Cyan -ForegroundColor black 
((Invoke-WebRequest 'https://api.myip.com/').content | ConvertFrom-Json).ip

Write-Host "`nSpeedTest" -BackgroundColor Cyan -ForegroundColor black 

#100M Testfile
$size = "100"
$in = "http://speedtest.frankfurt.linode.com/garbage.php?r=0.29286396544417626&ckSize=" + $size
$out = $env:temp +"\speedtest.bin"
$wc = New-Object System.Net.WebClient; "{0:N2} Mbit/sec" -f ((100/(Measure-Command {$wc.Downloadfile($in,$out)}).TotalSeconds)*8); del $out

$eventlogFiles = Get-WmiObject -Class Win32_NTEventlogFile

foreach ($eventlogFile in $eventlogFiles) {
    Write-Host $eventlogFile.LogFileName
    $path= "$DiagLogFolder\$($eventlogFile.LogFileName).evtx"
    $eventlogFile.BackupEventlog($path)
}




$eventLogs = Get-WinEvent -ListLog * -EA silentlycontinue
$recentEventLogs = $eventLogs | where-object { $_.recordcount -AND $_.lastwritetime -gt ( (get-date).AddHours(-5) ) }
$recentEvents = ( $recentEventLogs | foreach-object {
    Get-WinEvent -FilterHashtable @{
        LogName=$_.LogName
        Level=$logLevel
    } -MaxEvents 15 -ErrorAction SilentlyContinue
})

AppendReport -content (HtmlHeading -text "Recent Events") -raw
AppendReport -content ($recentEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message) -collapsible

Write-Host "`nFinished. Log written to $DiagLogName" -BackgroundColor Cyan -ForegroundColor black 

$htmlEnd | Out-File $htmlFilePath -Append

Start-Process "file:///$htmlFilePath"

Stop-Transcript