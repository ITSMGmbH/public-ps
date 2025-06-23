param (
    $timeDifferencethreshold = 2, # minutes
    $uptimeThreshold = 48, # hours
    $diskSizeThreshold = 20, # GB
    $freeMemoryThreshold = 15, # %
    $debug = "SilentlyContinue", # Stop, Inquire, Continue, SilentlyContinue
    $fileName= "SupportLog",
    $eventLogLevel = 2,
    # Verbose 	    5
    # Informational 4
    # Warning 	    3
    # Error 	    2
    # Critical 	    1
    # LogAlways 	0
    $centerDeviceLogLevel = "WARN",
    # DEBUG
    # INFO
    # WARN
    # ERROR
    [switch]$skipConnectivity
)

if($env:skipall) {
    return 0
}

#########
# Autor: (c) Marco.Hahnen@ITSM.de, Marc.Nonn@itsm.de
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

try {
    Stop-Transcript
}
catch [System.Management.Automation.PSInvalidOperationException] {

}

$tempPath = (Get-Item $env:temp).FullName

$fileName="ITSM-SupportLog"

$NowString = get-date -Format "MMddyyyy-HHmmss"
$DiagLogFileSuffix= "-$env:computername-$NowString"
$DiagLogFolder = "$tempPath\$fileName" 
$DiagLogName = "$DiagLogFolder\$fileName-$DiagLogFileSuffix.txt"
$DiagLogArchive = "$DiagLogFolder\$fileName-$DiagLogFileSuffix.zip"
$htmlFolder= "$DiagLogFolder\html"
$DiagLogFortiClientFolder = "$DiagLogFolder\FortiClientLog"
$DiagLogCenterdeviceFolder = "$DiagLogFolder\CenterdeviceLog"

$forticlientLogPath = "$($env:ProgramFiles)\Fortinet\FortiClient\logs\trace"
$centerDeviceLogPath = "$($env:USERPROFILE)\AppData\Local\CenterDevice\log\client.log"

if(Test-Path $DiagLogFolder) {
    Remove-Item -Recurse -Path $DiagLogFolder | out-null
}

if( !(Test-Path $DiagLogFolder) ) {
    New-Item -ItemType Directory $DiagLogFolder
}

if( !(Test-Path $htmlFolder) ) {
    New-Item -ItemType Directory $htmlFolder
}

Start-Transcript -Path $DiagLogName

$DebugPreference = $debug

Write-Debug "timeDifferencethreshold: $timeDifferencethreshold"
Write-Debug "uptimeThreshold: $uptimeThreshold"
Write-Debug "debug: $debug"
Write-Debug "fileName: $fileName"
Write-Debug "logLevel: $eventLogLevel"

$showDebug
if( ("Stop", "Inquire", "Continue") -contains $DebugPreference) {
    $showDebug = $true
}else {
    $showDebug = $false
}

$centerDeviceLogKeywords=$null
switch ($centerDeviceLogLevel) {
    "DEBUG" { 
        $centerDeviceLogKeywords= "DEBUG", "INFO" ,"WARN", "ERROR"
        break
    }
    "INFO" {
        $centerDeviceLogKeywords= "INFO" ,"WARN", "ERROR"
        break
    }
    "WARN" {
        $centerDeviceLogKeywords= "WARN", "ERROR"
        break
    }
    "ERROR" {
        $centerDeviceLogKeywords= "ERROR"
    }
    Default {
        $centerDeviceLogKeywords = "WARN", "ERROR"
    }
}



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
</script>
</body>
</html>"

$connectivitySummarys= @()

$htmlFilePath = "$htmlFolder\report.html"
$htmlHead | Out-File -LiteralPath $htmlFilePath -Force

function Get-Connectivity {
    param (
        $Target,
        $Type = "icmp",
        $Port,
        $Note = "n/a",
        $Source
    )
    $status = "success"

    switch ($type) {
        "icmp" { 
            Write-Debug "Pinging $Target..."
            $test = Test-NetConnection $Target
            if($test.PingSucceeded -eq "True") { 
                Write-Debug "Ping $Target succeeded"
                $status = "success"
            }
            else {
                Write-Debug "Ping $Target failed"
                $status = "failed"
            }

            break
        }
        "tcp" {
            Write-Debug "TcpTest $Target TCP Port $Port..."
            $test = Test-NetConnection $Target -Port $Port 
            if($test.TcpTestSucceeded -eq "True") { 
                Write-Debug "TcpTest $Target $Port succeeded"
                $status = "success"
            }
            else {
                Write-Debug "TcpTest $Target $Port failed"
                $status = "failed"
            }

            break
        }
        "traceroute" {
            Write-Debug "Traceroute $Target..."
            $test = Test-NetConnection $Target -TraceRoute
            if($test.PingSucceeded -eq "True") { 
                Write-Debug "TraceRoute $Target $Port succeeded"
                $status = "success"
            }
            else {
                Write-Debug "TraceRoute $Target $Port failed"
                $status = "failed"
            }

            break
        }
        "dns" {
            Write-Debug "Resolve $Target..."
            $test = $null
            try {
                if($null -eq $Source) {
                    $test = Resolve-DnsName $Target
                }else {
                    $test = Resolve-DnsName $Target -Server $Source
                }
                
            }catch [System.ComponentModel.Win32Exception] {
                $HREsult= [System.Convert]::ToString( ($_.Exception.hresult), 16 )
                switch ($HREsult) {
                    "80004005" {
                        Write-Debug "DNS not found"
                        $status = "failed"
                        break
                    }
                    Default {
                        Write-Debug "DNS Unknown Error"
                        $status = "failed"
                        break
                    }
                }
            }catch {
                Write-Debug "DNS Unknown Error"
                $status = "failed"
                break
            }
            
        }

        Default {
            throw "Type not specified"
        }
    }
    
    $test | Format-List | Out-Host

    $connectivitySummary = New-Object -TypeName psobject 

    Add-Member -InputObject $connectivitySummary -MemberType NoteProperty -Name Target -Value $Target
    Add-Member -InputObject $connectivitySummary -MemberType NoteProperty -Name Type -Value $Type
    Add-Member -InputObject $connectivitySummary -MemberType NoteProperty -Name Status -Value $status
    Add-Member -InputObject $connectivitySummary -MemberType NoteProperty -Name Note -Value $Note


    return $connectivitySummary
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
        $collapsibleTitle = "Expand",
        [switch]$noConsoleOut
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
        if(!$noConsoleOut) {
            $content | Format-List | Out-Host
        }
    }

    if($collapsible) {
        "</div>" | Out-File $htmlFilePath -Append
    }
    
}
function HtmlBulletPoints {
    param (
        $items
    )

    if($null -ne $items) {
        $html = "<ul>"
        foreach ($item in $items) {
            $html += "<li>$item</li>"
        }
        $html += "</ul>"
    
        return $html
    }else {
        return ""
    }

}

function Get-Disks {
    return (Get-PSDrive) | Where-Object {$_.Provider.Name -eq "FileSystem" -and $_.DisplayRoot -notlike "\\*" -and $_.Root.Split('\')[0] -notcontains ((Get-WmiObject Win32_CDROMDrive).Drive)}
}

function Get-Uptime {
    $lastBootTime = Get-Date (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime

    $now = Get-Date

    $uptime = ( ($now) - ($lastBootTime) ).TotalHours

    return [math]::Round($uptime, 2)
    
}

function Get-ForticlientConfig {
    $configTemplate = @{
        Name = $null
        Address = $null
        SaveUsername = $null
    }    


    if(Test-Path hklm:\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels) {
        $key = get-item hklm:\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels
        $tunnels = $key | Get-ChildItem
    
        $configs = @()
        foreach ($tunnel in $tunnels) {
            $tunnelProperties = ($tunnel | Get-ItemProperty)
            $config = [pscustomobject]$configTemplate

            $config.Name = $tunnel.PSChildName
            $config.Address = $tunnelProperties.Server
            $config.SaveUsername = [bool]$tunnelProperties.save_username
            $configs += $config
        }
        
        return $configs
    }else {
        Write-Debug "No Forticlient Config found"
        return $null
    }
    
}

function Check-KnownProblems {
    #setup
    $mailBody = HtmlHeading -text "Sent from $($env:USERDNSDOMAIN)\$($env:USERNAME)@$($env:COMPUTERNAME)"
    $problemReport = HtmlHeading -text "Problems detected"
    $warningReport = HtmlHeading -text "Warnings"
    $problemList = New-Object -TypeName 'System.Collections.ArrayList'
    $warningList = New-Object -TypeName 'System.Collections.ArrayList'
    $anyProblems = $false
    $anyWarnings = $false

    #problems
    $timeDifference = Check-TimeDifference
    if($timeDifference -ne 0) {
        $anyProblems = $true
        $problemList.Add("Time Difference $timeDifference Minutes") | Out-Null
    }
    
    if(!(Check-DomainTrust)) {
        $anyProblems = $true
        $problemList.Add("Domain trustrelationship failed. Try Test-ComputerSecureChannel -Repair") | Out-Null
    }


    #warnings
    $uptime = Check-Uptime
    if($uptime -ne 0) {
        $anyWarnings = $true
        $warningList.Add("Uptime is $uptime hours.") | Out-Null
    }

    $lowDrives = Check-FreeDiskSpace
    if($null -ne $lowDrives) {
        $anyWarnings = $true
        $warningList.Add("Low Disk Space")  | Out-Null
        foreach ($lowDrive in $lowDrives) {
            $str = "Drive: $($lowDrive.Name), Used: $([math]::Round( ($lowDrive.Used/1GB), 2) ), Free: $([math]::Round( ($lowDrive.Free/1GB), 2) )"
            $warningList.Add($str) | Out-Null
        }
    }

    $cdLines = Check-CenterdeviceLogs

    if($cdLines.Count -le 10 -and $cdLines -ne 0) {
        $anyWarnings = $true
        $warningList.Add("Centerdevice Errors") | Out-Null
        foreach($line in $cdLines) {
            $warningList.Add($line) | Out-Null
        }
    }elseif ($cdLines.Count -gt 10 -and $cdLines -ne 0) {
        $anyWarnings = $true
        $warningList.Add("$($cdLines.Count) Centerdevice Errors! See $DiagLogCenterdeviceFolder for details") | Out-Null
    }

    $freeMemPercent = Check-FreeMemory
    if($freeMemPercent -lt $freeMemoryThreshold) {
        $anyWarnings = $true
        $warningList.Add("Low Memory. $freeMemPercent%") | Out-Null
    }


    #output

    if($warningList.Count -gt 0 ) {
        Write-Host -BackgroundColor Yellow -ForegroundColor Black "Warnings:"
        $warningList | Format-List | Out-Host
    }

    if($problemList.Count -gt 0 ) {
        Write-Host -BackgroundColor Red -ForegroundColor White "Problems detected:"
        $problemList | Format-List | Out-Host
    }
    
    if($anyProblems) {
        AppendReport -content $problemReport -raw | Out-Null
    }

    if($anyWarnings) {
        AppendReport -content $warningReport -raw | Out-Null
    }

}

function Check-TimeDifference {

    $timeApiRequest = $null
    $networktime = $null

    $timeApiRequest = ( ( (Invoke-WebRequest -UseBasicParsing "https://www.timeapi.io/api/Time/current/zone?timeZone=Europe/Amsterdam").content) | ConvertFrom-Json)

    $networktime = Get-Date  $timeApiRequest.datetime 

    $timeDifference = [math]::Abs( ( ($networktime) - ($localtime) ).TotalMinutes)
    
    if( $timeDifference -gt $timeDifferencethreshold) {
        return [math]::Round($timeDifference, 2)
    }else {
        return 0
    }
}

function Check-Uptime {

    if($simulateUptimeWarning) {
        $now = (Get-Date).AddDays(30)
    }else {
        $now = Get-Date
    }

    $uptime = Get-Uptime

    if($uptime -gt $uptimeThreshold) {
        return $uptime
    }else {
        return 0
    }
}

function Check-DomainTrust {
    if($simulateDomainTrustProblem) {
        return $false
    }else {
        
        $result = $null
        try {
            $result = Test-ComputerSecureChannel
        }catch [System.InvalidOperationException] {
            $true
        }
        return $result
    }
}

function Check-FreeDiskSpace {
    return Get-Disks | Where-Object {$_.Free/1GB -lt $diskSizeThreshold}
}

function Copy-ForticlientLogs {

    if( !(Test-Path $forticlientLogPath) ) {
        Write-Debug "No Forticlient Logs available"
        return 0
    }

    if(! (Test-Path $DiagLogFortiClientFolder) ) {
        New-Item -ItemType Directory -Path $DiagLogFortiClientFolder
    }

    $forticlientLogFile = Get-Content "$forticlientLogPath\sslvpndaemon_1.log" -Tail 10000
    $forticlientLogFile | Out-File "$DiagLogFortiClientFolder\sslvpndaemon_1.log"


    # $forticlientLogFiles= Get-ChildItem $forticlientLogPath -Filter "sslvpndaemon_*.log"
    # foreach ($forticlientLogFile in $forticlientLogFiles) {
    #     $forticlientLogFile | Copy-Item -Destination "$DiagLogFortiClientFolder\$forticlientLogFile"
    # }   
}

function Copy-ForticlientConfig {

    if( (Test-Path "HKLM:\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels") ) {
        reg export HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels "$DiagLogFortiClientFolder\vpn-config.reg.txt"
    }else {
        Write-Debug "No Forticlient Config available"
    }

}

function Copy-CenterdeviceLogs {
    if(! (Test-Path $centerDeviceLogPath) ) {
        Write-Debug "No Centerdevice Logs available"
        return 0
    }

    if(! (Test-Path $DiagLogCenterdeviceFolder)) {
        New-Item -ItemType Directory -Path $DiagLogCenterdeviceFolder
    }

    Copy-Item -Path $centerDeviceLogPath -Destination "$DiagLogCenterdeviceFolder\client.log"

}

function Check-CenterdeviceLogs {

    if(! (Test-Path $centerDeviceLogPath) ) {
        Write-Debug "No Centerdevice Logs available"
        return 0
    }

    $log = Get-Content $centerDeviceLogPath
    
    return $log | Select-String $centerDeviceLogKeywords
}

function Check-FreeMemory {
    $totalRam = (Get-CIMInstance Win32_OperatingSystem | Select TotalVisibleMemorySize).TotalVisibleMemorySize / 1MB
    $freeRAM = (Get-CIMInstance Win32_OperatingSystem | Select FreePhysicalMemory).FreePhysicalMemory / 1MB
    $percent = [Math]::Round(($totalRAM / $freeRAM), 2) * 10
    return $percent
}

Write-Host "Please Wait..."

Write-Host "Check Adminrole" -BackgroundColor Cyan -ForegroundColor black 
if(Test-Administrator)
{
    Write-Debug "User is admin"
}
else
{
    Write-Debug "User is not admin"
}

Write-Host "Systeminfo" -BackgroundColor Cyan -ForegroundColor black 
Write-Debug systeminfo

$publicIp= ((Invoke-WebRequest -UseBasicParsing 'https://api.myip.com/').content | ConvertFrom-Json).ip

$systeminfo = Get-ComputerInfo
$systeminfo | Format-List

$uptime = Get-Uptime

$rdpClientKey = Get-Item HKLM:"\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
$rdpUDPDisabled = $rdpClientKey.Property -contains "fclientdisableudp"

$generalSummary = [PSCustomObject]@{
    Hostname = $systeminfo.CsCaption
    IsAdmin = (Test-Administrator)
    Uptime = "$uptime h"
    LastBootTime = $systeminfo.OsLastBootUpTime
    ServiceTag = $systeminfo.BiosSeralNumber
    "RDP UDP Disabled" = $rdpUDPDisabled
    PublicIp = $publicIp
    WindowsEdition = $systeminfo.OsName
    WindowsVersion = $systeminfo.OsVersion
}

cmd /c "netsh wlan show all >$($DiagLogFolder)\netsh.txt"

Write-Host "Logged on Users" -BackgroundColor Cyan -ForegroundColor black 
quser

AppendReport -content (HtmlHeading -text "General info") -raw
AppendReport -content $generalSummary
AppendReport -content (
    Get-Disks | Select-Object Name, @{
        Name="Used (GB)";Expression={ [math]::Round( ($_.Used / 1GB), 2 ) }
    }, @{
        Name="Free (GB)";Expression={ [math]::Round( ($_.Free / 1GB), 2 ) }
    }
)

AppendReport -content (HtmlHeading -text "Forticlient Configs") -raw
AppendReport -content (Get-ForticlientConfig)

AppendReport -content (HtmlHeading -text "Printer") -raw
AppendReport -content (Get-Printer | Select-Object Name, Comment, PrinterStatus, Type, DriverName, PortName, JobCount) -noConsoleOut
AppendReport -content (Get-Printer | Select-Object *) -collapsible

Write-Host "Running Processes" -BackgroundColor Cyan -ForegroundColor black 
if(Test-Administrator)
{
    Get-Process -IncludeUserName | Format-Table
}
else
{
    Get-Process | Format-Table
}

Write-Host "Services" -BackgroundColor Cyan -ForegroundColor black 

if($showDebug) {
    Get-Service | Format-Table
}

AppendReport -content (HtmlHeading -text "Services") -raw
AppendReport -content (Get-Service | Select-Object DisplayName, ServiceName, Status, StartType) -collapsible

AppendReport -content (HtmlHeading -text "Stopped Auto Services") -raw
AppendReport -content (Get-Service | Where-Object {$_.StartType -like "*auto*" -and $_.Status -like "*stop*" } | Select-Object DisplayName, ServiceName, Status, StartType)

Write-Host "IPConfig" -BackgroundColor Cyan -ForegroundColor black 
ipconfig /all

$adapters = Get-NetAdapter | Select-Object *
$IPConfigs = Get-NetIPConfiguration | Select-Object *

$NetConfigs = @()

$OFS = ", "
foreach ($adapter in $adapters) {
    $NetConfigs += [pscustomobject]@{
        Name = $adapter.Name
        Description = $adapter.InterfaceDescription
        Status = $adapter.Status
        MAC = $adapter.MacAddress
        IP = [string](($IPConfigs | Where-Object {$_.NetAdapter.ifIndex -eq $adapter.ifIndex}).IPv4Address.IPAddress)
        GW = [string](($IPConfigs | Where-Object {$_.NetAdapter.ifIndex -eq $adapter.ifIndex}).IPV4DefaultGateway.NextHop)
        DNS = [string](($IPConfigs | Where-Object {$_.NetAdapter.ifIndex -eq $adapter.ifIndex}).DNSServer.ServerAddresses)
    } 

}
$OFS = " "

AppendReport -content (HtmlHeading -text "IPConfig") -raw
AppendReport -content $NetConfigs -collapsible -noConsoleOut

$NetConfigs | Format-Table -AutoSize -Wrap

Write-Host "WifiNetworks" -BackgroundColor Cyan -ForegroundColor black 
AppendReport -content (HtmlHeading -text "WifiNetworks") -raw
$WifiNetworks = netsh wlan show interfaces
$WifiNetworks
AppendReport -content $WifiNetworks -raw

Write-Host "Routing" -BackgroundColor Cyan -ForegroundColor black 

$upIndices = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object ifIndex).ifIndex
$ipv4Routes = Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $upIndices | Select-Object @{
        Name = "Interface";Expression={(Get-NetAdapter -InterfaceIndex $_.ifIndex | Select-Object Name).Name}
    },
    @{
        Name = "Interface Description"; Expression = {(Get-NetAdapter -InterfaceIndex $_.ifIndex | Select-Object InterfaceDescription).InterfaceDescription}
    },
    DestinationPrefix,
    NextHop,
    RouteMetric,
    ifMetric

AppendReport -raw -content (HtmlHeading -text "Routing")
AppendReport -collapsible -noConsoleOut -content $ipv4Routes 

Get-NetRoute | Format-Table -AutoSize -Wrap

Write-Host "DNS Cache" -BackgroundColor Cyan -ForegroundColor black 

AppendReport -raw -content (HtmlHeading -text "DNS Cache")
AppendReport -collapsible -content (Get-DnsClientCache | Select-Object Name, Data, TTL) -noConsoleOut

Get-DnsClientCache | Format-Table -AutoSize -Wrap

if(!$skipConnectivity) {
    Write-Host "Connectivity Tests" -BackgroundColor Cyan -ForegroundColor black 
    $NetIPConfiguration = Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -ne "Disconnected"}
    
    $dnsservers = ($NetIPConfiguration | Select-Object -ExpandProperty DNSServer | ? AddressFamily -eq "2").ServerAddresses | select -Unique
    foreach ($dnsserver in $dnsservers) {
    
        $connectivitySummarys += (Get-Connectivity -Target $dnsserver -Note "Local Resolver")
        
        Write-Debug "Test DNS Server $dnsserver resolve vpn.itsm.de"
        $connectivitySummarys += (Get-Connectivity -Target "vpn.itsm.de" -Type "dns" -Note "@$dnsserver" -Source $dnsserver)
    }
    
    $Gateways = ($NetIPConfiguration | select -ExpandProperty IPV4DefaultGateway).NextHop
    foreach($Gateway in $Gateways)
    {
        $connectivitySummarys += (Get-Connectivity -Target $Gateway -Note "Gateway")
    }
    
    $connectivitySummarys += (Get-Connectivity -Target vpn.itsm.de -type tcp -Port 443 -Note "General Connectivity")
    $connectivitySummarys += (Get-Connectivity -Target vpn.itsm.de -type traceroute -Note "General Connectivity")
    $connectivitySummarys += (Get-Connectivity -Target google.de -type tcp -Port 443 -Note "General Connectivity")
    $connectivitySummarys += (Get-Connectivity -Target google.de -type traceroute -Note "General Connectivity")
    $connectivitySummarys += (Get-Connectivity -Target 8.8.8.8 -type traceroute -Note "General Connectivity")
    
    AppendReport -content (HtmlHeading -text "Successfull Connectivity")  -raw
    AppendReport -content ($connectivitySummarys | Where-Object {$_.Status -eq "success"})
    AppendReport -content (HtmlHeading -text "Failed Connectivity")  -raw
    AppendReport -content ($connectivitySummarys | Where-Object {$_.Status -eq "failed"})
    AppendReport -content (HtmlHeading -text "Disconnected Network Adapters" -size "4") -raw
    AppendReport -content (Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq "Disconnected"} | Select-Object InterfaceAlias)
}


Write-Host "Public IP" -BackgroundColor Cyan -ForegroundColor black 
$publicIp

Write-Host "SpeedTest" -BackgroundColor Cyan -ForegroundColor black 

#100M Testfile
$size = "100"
$in = "http://speedtest.frankfurt.linode.com/garbage.php?r=0.29286396544417626&ckSize=" + $size
$out = $tempPath +"\speedtest.bin"
$wc = New-Object System.Net.WebClient; "{0:N2} Mbit/sec" -f ((100/(Measure-Command {$wc.Downloadfile($in,$out)}).TotalSeconds)*8); del $out

$eventlogFiles = Get-WmiObject -Class Win32_NTEventlogFile

Write-Debug "Getting Eventlogs:"
foreach ($eventlogFile in $eventlogFiles) {
    Write-Debug $eventlogFile.LogFileName
    $path= "$DiagLogFolder\$($eventlogFile.LogFileName)$DiagLogFileSuffix.evtx"
    $eventlogFile.BackupEventlog($path) | Out-Null
}


$eventLogs = Get-WinEvent -ListLog * -EA silentlycontinue
$recentEventLogs = $eventLogs | where-object { $_.recordcount -AND $_.lastwritetime -gt ( (get-date).AddHours(-5) ) }
$recentEvents = ( $recentEventLogs | foreach-object {
    Get-WinEvent -FilterHashtable @{
        LogName=$_.LogName
        Level=$eventLogLevel
    } -MaxEvents 15 -ErrorAction SilentlyContinue
})

AppendReport -content (HtmlHeading -text "Recent Events") -raw
AppendReport -content ($recentEvents | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message) -collapsible -noConsoleOut

Write-Debug "Copying Forticlient Logs"
Copy-ForticlientLogs
Copy-ForticlientConfig
Copy-CenterdeviceLogs

Start-Process gpresult -ArgumentList "/scope:user", "/h $($DiagLogFolder)\gpresult_user.html" -Wait
if(Test-Administrator) {
    Start-Process gpresult -Verb runas -ArgumentList "/scope:computer", "/h $($DiagLogFolder)\gpresult_computer.html" -Wait
}

$body = Check-KnownProblems

Write-Host "Finished. Log written to $DiagLogName" -BackgroundColor Cyan -ForegroundColor black 

$htmlEnd | Out-File $htmlFilePath -Append

Stop-Transcript

Compress-Archive $DiagLogFolder -DestinationPath $DiagLogArchive -Force

Write-Host -ForegroundColor White -BackgroundColor Red "Logs $DiagLogFolder"
Invoke-Item $DiagLogFolder
pause
