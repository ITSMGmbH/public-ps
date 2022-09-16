param (
    $mailTo,
    $timeDifferencethreshold = 2, # minutes
    $uptimeThreshold = 2, # days
    $debug = "SilentlyContinue", # Stop, Inquire, Continue, SilentlyContinue
    $fileName= "SupportLog",
    $logLevel = 2,
    # Verbose 	    5
    # Informational 4
    # Warning 	    3
    # Error 	    2
    # Critical 	    1
    # LogAlways 	0
    $smtpUser,
    $smtpPW,
    $smtpServer,
    $smtpPort,
    $smtpTo,
    $smtpSubject = "Support Script",
    $smtpFrom,
    [switch]$simulateTimeProblem,
    [switch]$simulateDomainTrustProblem,
    [switch]$simulateUptimeWarning
)

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

$smtpPorts = 25, 587, 465, 2525

$NowString = get-date -Format "MMddyyyy-HHmmss"
$DiagLogFileSuffix= "-$env:computername-$NowString"
$DiagLogFolder = "$($env:temp)\$fileName" 
$DiagLogName = "$DiagLogFolder\$fileName-$DiagLogFileSuffix.txt"
$DiagLogArchive = "$DiagLogFolder\$fileName-$DiagLogFileSuffix.zip"
$htmlFolder= "$DiagLogFolder\html"
$DiagLogFortiClientFolder = "$DiagLogFolder\FortiClientLog"

$forticlientLogPath = "$($env:ProgramFiles)\Fortinet\FortiClient\logs\trace"

if(Test-Path $DiagLogFolder) {
    Remove-Item -Recurse -Path $DiagLogFolder
}

if( !(Test-Path $DiagLogFolder) ) {
    New-Item -ItemType Directory $DiagLogFolder
}

if( !(Test-Path $htmlFolder) ) {
    New-Item -ItemType Directory $htmlFolder
}

Start-Transcript -Path $DiagLogName

$DebugPreference = $debug

Write-Debug "mailTo: $mailTo"
Write-Debug "timeDifferencethreshold: $timeDifferencethreshold"
Write-Debug "uptimeThreshold: $uptimeThreshold"
Write-Debug "debug: $debug"
Write-Debug "fileName: $fileName"
Write-Debug "logLevel: $logLevel"
Write-Debug "smtpUser: $smtpUser"
Write-Debug "smtpServer: $smtpServer"
Write-Debug "smtpPort: $smtpPort"
Write-Debug "smtpTo: $smtpTo"
Write-Debug "smtpSubject: $smtpSubject"
Write-Debug "smtpFrom: $smtpFrom"
Write-Debug "simulateTimeProblem:  $simulateTimeProblem"
Write-Debug "simulateDomainTrustProblem: $simulateDomainTrustProblem"
Write-Debug "simulateUptimeWarning: $simulateUptimeWarning"

$showDebug
if( ("Stop", "Inquire", "Continue") -contains $DebugPreference) {
    $showDebug = $true
}else {
    $showDebug = $false
}

if($null -ne $smtpPort) {
    $smtpPorts = $smtpPort
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
</script
</body>
</html>"

$connectivitySummarys= @()

$generalSummary = New-Object -TypeName psobject 
Add-Member -InputObject $generalSummary -MemberType NoteProperty -Name hostname -Value $null
Add-Member -InputObject $generalSummary -MemberType NoteProperty -Name isAdmin -Value $null
Add-Member -InputObject $generalSummary -MemberType NoteProperty -Name Uptime -Value $null
Add-Member -InputObject $generalSummary -MemberType NoteProperty -Name lastBootTime -Value $null
#Add-Member -InputObject $generalSummary -MemberType NoteProperty -Name loggedOnUsers -Value $null


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

function Send-OutlookMail {
    param (
        $subject="ITSM Support Script",
        $to,
        $body = "Sent from $($env:USERDNSDOMAIN)\$($env:USERNAME)@$($env:COMPUTERNAME)",
        $attachments = $DiagLogArchive
    )

    $returncode = 0

    $failed = $false
    try {
        $Outlook = New-Object -ComObject Outlook.Application
    }catch [System.Runtime.InteropServices.COMException] {
        $HREsult = [System.Convert]::ToString( ($_.Exception.hresult), 16 )
        $returncode = $HREsult
        $failed = $true
    }catch {
        $returncode = -1
        $failed = $true
    }

    if(!$failed) {
        $Mail = $Outlook.CreateItem(0)
        $Mail.subject=$subject
        $Mail.To = $to
        $Mail.HTMLBody = $body 
        $Mail.Attachments.Add($attachments)

        try {
            $Mail.send()
        }catch [System.Runtime.InteropServices.COMException] {
            $HREsult = [System.Convert]::ToString( ($_.Exception.hresult), 16 )
            $returncode = $HREsult
            $failed = $true
        }catch {
            $returncode = -1
            $failed = $true
        }        
    }

    return $returncode
    
}

function Send-Mail {
    param (
        $subject,
        $to,
        $from,
        $port,
        $server,
        $body = "Sent from $($env:USERDNSDOMAIN)\$($env:USERNAME)@$($env:COMPUTERNAME)",
        $attachments = $DiagLogArchive,
        $mailCred
    )

    if($null -eq $from -or $null -eq $to -or $null -eq $port -or $null -eq $server) {
        return 1
    }

    $returncode = 0
    try {
        Send-MailMessage -Subject $subject -To $to -From $from -Body $body -SmtpServer $server -Attachments $attachments -UseSsl -Credential $mailCred
    }catch [System.Net.Mail.SmtpException] {
        $HREsult = [System.Convert]::ToString( ($_.Exception.hresult), 16 )
        $returncode = $HREsult
    }
    catch {
        $returncode = -1
    }

    return $returncode   
    
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



    #output
    if($problemList.Count -gt 0 ) {
        Write-Debug "Problems detected:"
        $problemList | Format-List | Out-Host
    }

    if($warningList.Count -gt 0 ) {
        Write-Debug "Warnings:"
        $warningList | Format-List | Out-Host
    }
    
    $problemReport += HtmlBulletPoints -items $problemList
    $warningReport += HtmlBulletPoints -items $warningList

    AppendReport -content $problemReport -raw
    AppendReport -content $warningReport -raw

    if($anyProblems) {
        $mailBody += $problemReport
    }

    if($anyWarnings) {
        $mailBody += $warningReport
    }

    return $mailBody
}

function Check-TimeDifference {

    $networktimeInfo = ( ( (Invoke-WebRequest -UseBasicParsing "http://worldtimeapi.org/api/timezone/Europe/Berlin").content) | ConvertFrom-Json)
    $networktime = Get-Date  $networktimeInfo.datetime 
    if($simulateTimeProblem) {
        $localtime = (Get-Date).AddMinutes(15)
    }else {
        $localtime = Get-Date
    }
    $timeDifference = [math]::Abs( ( ($networktime) - ($localtime) ).TotalMinutes)
    
    if( $timeDifference -gt $timeDifferencethreshold) {
        return [math]::Round($timeDifference, 2)
    }else {
        return 0
    }
}

function Check-Uptime {

    $lastBootTime = Get-Date (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime

    if($simulateUptimeWarning) {
        $now = (Get-Date).AddDays(30)
    }else {
        $now = Get-Date
    }

    if($lastBootTime.AddDays($uptimeThreshold) -lt $now ) {
        $uptime = [math]::Abs( ( ($now) - ($lastBootTime) ).TotalHours )
        return [math]::Round($uptime, 2)
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
    try {
        reg export HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels "$DiagLogFortiClientFolder\vpn-config.reg"
    }catch {
        Write-Debug "Forticlient Reg Export failed"
        return 1
    }
    
}

Write-Host "Please Wait..."

Write-Host "`nCheck Adminrole" -BackgroundColor Cyan -ForegroundColor black 
if(Test-Administrator)
{
    Write-Debug "User is admin"
    $generalSummary.isAdmin = $true
}
else
{
    Write-Debug "User is not admin"
    $generalSummary.isAdmin = $false
}

Write-Host "`nSysteminfo" -BackgroundColor Cyan -ForegroundColor black 
Write-Debug systeminfo

$systeminfo = Get-ComputerInfo

$uptime = $systeminfo.OsUptime.toString()
$utHours = $uptime.Split('.')[0]
$utMinutes = $uptime.Split('.')[1].Split(':')[0]
$generalSummary.Uptime = "$utHours h, $utMinutes min"
$generalSummary.lastBootTime = $systeminfo.OsLastBootUpTime
$generalSummary.hostname = $systeminfo.CsCaption



Write-Host "`nLogged on Users" -BackgroundColor Cyan -ForegroundColor black 
quser

AppendReport -content (HtmlHeading -text "General info") -raw
AppendReport -content $generalSummary

Write-Host "`nRunning Processes" -BackgroundColor Cyan -ForegroundColor black 
if(Test-Administrator)
{
    Get-Process -IncludeUserName | Format-Table
}
else
{
    Get-Process | Format-Table
}

Write-Host "`nServices" -BackgroundColor Cyan -ForegroundColor black 

if($showDebug) {
    Get-Service | Format-Table
}

AppendReport -content (HtmlHeading -text "Services") -raw
AppendReport -content (Get-Service | Select-Object DisplayName, ServiceName, Status, StartType) -collapsible

AppendReport -content (HtmlHeading -text "Stopped Auto Services") -raw
AppendReport -content (Get-Service | Where-Object {$_.StartType -like "*auto*" -and $_.Status -like "*stop*" } | Select-Object DisplayName, ServiceName, Status, StartType)

Write-Host "`nIPConfig" -BackgroundColor Cyan -ForegroundColor black 
ipconfig /all



Write-Host "`nRouting" -BackgroundColor Cyan -ForegroundColor black 
route print

Write-Host "`nConnectivity Tests" -BackgroundColor Cyan -ForegroundColor black 
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


Write-Host "`nPublic IP" -BackgroundColor Cyan -ForegroundColor black 
((Invoke-WebRequest -UseBasicParsing 'https://api.myip.com/').content | ConvertFrom-Json).ip

Write-Host "`nSpeedTest" -BackgroundColor Cyan -ForegroundColor black 

#100M Testfile
$size = "100"
$in = "http://speedtest.frankfurt.linode.com/garbage.php?r=0.29286396544417626&ckSize=" + $size
$out = $env:temp +"\speedtest.bin"
$wc = New-Object System.Net.WebClient; "{0:N2} Mbit/sec" -f ((100/(Measure-Command {$wc.Downloadfile($in,$out)}).TotalSeconds)*8); del $out

$eventlogFiles = Get-WmiObject -Class Win32_NTEventlogFile

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
        Level=$logLevel
    } -MaxEvents 15 -ErrorAction SilentlyContinue
})

AppendReport -content (HtmlHeading -text "Recent Events") -raw
AppendReport -content ($recentEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message) -collapsible

Write-Debug "Copying Forticlient Logs"
Copy-ForticlientLogs
Copy-ForticlientConfig

$body = Check-KnownProblems

Write-Host "`nFinished. Log written to $DiagLogName" -BackgroundColor Cyan -ForegroundColor black 

$htmlEnd | Out-File $htmlFilePath -Append

Stop-Transcript

Compress-Archive $DiagLogFolder -DestinationPath $DiagLogArchive -Force

$sent = $false
switch ( (Send-OutlookMail -body $body -to $mailTo) ) {
    0 {
        Write-Debug "Mail send succesfully"
        $sent = $true
    }
    "80040154" {
        Write-Debug "Outlook not available, cant send Mail"
        break
    }
    "80004005" {
        Write-Debug "No MailTo provided, cant send Mail"
        break
    }
    -1 {
        Write-Debug "Unknown Error, cant send Mail"
        break
    }
    Default {}
}

if(!$sent) {
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $smtpUser, (ConvertTo-SecureString -AsPlainText -Force -String $smtpPW)
    

    switch ( (Send-Mail -to $smtpTo -subject $smtpSubject -from $smtpFrom -port $smtpPort -server $smtpServer -mailCred $cred) ) {
        0 {
            Write-Debug "Mail send succesfully"
            $sent = $true
        }
        1 {
            Write-Debug "Missing Mail Paramater"
        }
        -1 {
            Write-Debug "Unknown Error"
        }
        Default {}
    }
}



if(!$sent) {
    Write-Host -ForegroundColor White -BackgroundColor Red "Couldnt send mail, copy Zip at $DiagLogFolder manually!"
    Invoke-Item $DiagLogFolder
    pause
}