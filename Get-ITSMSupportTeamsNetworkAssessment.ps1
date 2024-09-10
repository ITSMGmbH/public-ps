#########
# Autor: Marco.Hahnen@ITSM.de
# Zweck: Teams Network Assessment Tool Automation
# Version: 0.1
# Read: https://itsmgmbh.atlassian.net/wiki/spaces/KB/pages/505282561/Microsoft+Teams+Network+Assessment+Tool
# Requires: https://www.microsoft.com/en-us/download/details.aspx?id=103017
# Execution: IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/ITSMGmbH/public-ps/main/Get-ITSMSupportTeamsNetworkAssessment.ps1')
# ChangeLog
# - 0.1: inital Release work in Progress
#########

if(-Not (Test-Path "c:\temp")) {
    New-Item -ItemType Directory c:\temp
}
$now = get-date -Format 'yyyymmdd-hhMMss'
Start-Transcript c:\temp\Teams-$now.txt

cd "C:\Program Files (x86)\Microsoft Teams Network Assessment Tool"
.\NetworkAssessmentTool.exe | Out-Default
.\NetworkAssessmentTool.exe /qualitycheck | Out-Default
.\NetworkAssessmentTool.exe /qualitycheckweb | Out-Default
.\NetworkAssessmentTool.exe /infraconnectivitytest | Out-Default
.\NetworkAssessmentTool.exe /interfaces | Out-Default
.\NetworkAssessmentTool.exe /location | Out-Default

Get-ChildItem "$env:LOCALAPPDATA\Microsoft Teams Network Assessment Tool\" | Where-Object {$_.Lastwritetime -gt (get-date).Adddays(-1)} | Compress-Archive -DestinationPath "c:\temp\MicrosoftTeamsNetworkAssessmentTool-$($env:COMPUTERNAME)-$($now).zip

Stop-Transcript
Compress-Archive -Path "c:\temp\Teams-$now.txt" -DestinationPath "c:\temp\MicrosoftTeamsNetworkAssessmentTool-$($env:COMPUTERNAME)-$($now).zip -Update