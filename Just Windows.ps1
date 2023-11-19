# DEBLOAT SCRIPT BY ZOIC
# THIS SCRIPT WILL COMPLETELY DEBLOAT WINDOWS DOWN TO ONLY THE BASICS
# SOME FEATURES MAY BE BROKEN OR MISSING


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}



$Bloatware = @(
                #Unnecessary Windows 10 AppX Apps
                "3DBuilder"
                "Microsoft3DViewer"
                "AppConnector"
                "BingFinance"
                "BingNews"
                "BingSports"
                "BingTranslator"
                "BingWeather"
                "BingFoodAndDrink"
                "BingHealthAndFitness"
                "BingTravel"
                "MinecraftUWP"
                "GamingServices"
                "GetHelp"
                "Getstarted"
                "Messaging"
                "Microsoft3DViewer"
                "MicrosoftSolitaireCollection"
                "NetworkSpeedTest"
                "News"
                "Lens"
                "Sway"
                "OneNote"
                "OneConnect"
                "People"
                "Paint3D"
                "Photos"
                "MicrosoftStickyNotes"
                "SkypeApp"
                "Todos"
                "Wallet"
                "Whiteboard"
                "WindowsAlarms"
                "windowscommunicationsapps"
                "WindowsFeedbackHub"
                "WindowsMaps"
                "WindowsPhone"
                "WindowsSoundRecorder"
                "ConnectivityStore"
                "CommsPhone"
                "ScreenSketch"
                "MixedReality.Portal"
                "ZuneMusic"
                "ZuneVideo"
                "YourPhone"
                "MicrosoftOfficeHub"
                "WindowsStore"
                "WindowsCamera"
                "WindowsCalculator"
                "HEIFImageExtension"
                "StorePurchaseApp"
                "VP9VideoExtensions"
                "WebMediaExtensions"
                "WebpImageExtension"
                "DesktopAppInstaller"
                #Sponsored Windows 10 AppX Apps
                #Add sponsored/featured apps to remove in the "*AppName*" format
                "EclipseManager"
                "ActiproSoftwareLLC"
                "AdobeSystemsIncorporated.AdobePhotoshopExpress"
                "Duolingo-LearnLanguagesforFree"
                "PandoraMediaInc"
                "CandyCrush"
                "BubbleWitch3Saga"
                "Wunderlist"
                "Flipboard"
                "Twitter"
                "Facebook"
                "Royal Revolt"
                "Sway"
                "Speed Test"
                "Dolby"
                "Viber"
                "ACGMediaPlayer"
                "Netflix"
                "OneCalendar"
                "LinkedInforWindows"
                "HiddenCityMysteryofShadows"
                "Hulu"
                "HiddenCity"
                "AdobePhotoshopExpress"
                "HotspotShieldFreeVPN"

               
                "Advertising"
                

                # HPBloatware Packages
                "HPJumpStarts"
                "HPPCHardwareDiagnosticsWindows"
                "HPPowerManager"
                "HPPrivacySettings"
                "HPSupportAssistant"
                "HPSureShieldAI"
                "HPSystemInformation"
                "HPQuickDrop"
                "HPWorkWell"
                "myHP"
                "HPDesktopSupportUtilities"
                "HPQuickTouch"
                "HPEasyClean"
                "HPSystemInformation"
            )
                            #   Description:
# This script will remove and disable OneDrive integration.



Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}


Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.exe"

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting 5 seconds for explorer to complete loading"
Start-Sleep 5


             ## Teams Removal - Source: https://github.com/asheroto/UninstallTeams
            function getUninstallString($match) {
                return (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$match*" }).UninstallString
            }
            
            $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
            $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
            
            Write-Output "Stopping Teams process..."
            Stop-Process -Name "*teams*" -Force -ErrorAction SilentlyContinue
        
            Write-Output "Uninstalling Teams from AppData\Microsoft\Teams"
            if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
                # Uninstall app
                $proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru
                $proc.WaitForExit()
            }
        
            Write-Output "Removing Teams AppxPackage..."
            Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        
            Write-Output "Deleting Teams directory"
            if ([System.IO.Directory]::Exists($TeamsPath)) {
                Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
            }
        
            Write-Output "Deleting Teams uninstall registry key"
            # Uninstall from Uninstall registry key UninstallString
            $us = getUninstallString("Teams");
            if ($us.Length -gt 0) {
                $us = ($us.Replace("/I", "/uninstall ") + " /quiet").Replace("  ", " ")
                $FilePath = ($us.Substring(0, $us.IndexOf(".exe") + 4).Trim())
                $ProcessArgs = ($us.Substring($us.IndexOf(".exe") + 5).Trim().replace("  ", " "))
                $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
                $proc.WaitForExit()
            }
            
           taskkill.exe /F /IM "SkypeApp.exe"
           taskkill.exe /F /IM "Skype.exe"
           
            foreach ($Bloat in $Bloatware) {
                Get-AppXPackage "*$Bloat*" -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
               Get-AppxPackage "*$Bloat*" | Remove-AppxPackage -ErrorAction SilentlyContinue 
               Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Bloat*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                
                

                Write-Host "Trying to remove $Bloat."
                
            }

            
                
                if(Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq Microsoft Update Health Tools"})
                {
                $MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq Microsoft Update Health Tools"}
                $MyApp.Uninstall()
                }

                 if(Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -like *Update for Windows 10*"})
                {
                $MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -like *Update for Windows 10*"}
                $MyApp.Uninstall()
                }
                      
                
                Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
                Get-AppxPackage Microsoft.Xbox.TCUI | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxGameOverlay | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxGamingOverlay | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxIdentityProvider | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage
                Get-AppxPackage -allusers Microsoft.MSPaint | Remove-AppxPackage
                Get-AppxPackage -allusers Microsoft.OneDriveSync | Remove-AppxPackage
                Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
                Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage 


        # edge removal
Write-host "GETTING EDGE REMOVAL SCRIPT"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/zoicware/EdgeRemove/main/EdgeRemoval.bat" -OutFile "EdgeRemove.bat" 
        start-process -FilePath "C:\Windows\System32\EdgeRemove.bat" -Wait
        Remove-item -Path "C:\Scripts" -Force -Recurse
        Remove-Item -Path "C:\Windows\System32\EdgeRemove.bat" -Force

        $START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$layoutFile="C:\Windows\StartMenuLayout.xml"

#Delete layout file if it already exists
If(Test-Path $layoutFile)
{
    Remove-Item $layoutFile
}

#Creates the blank layout file
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

$regAliases = @("HKLM", "HKCU")

#Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    IF(!(Test-Path -Path $keyPath)) { 
        New-Item -Path $basePath -Name "Explorer"
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}

#Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
kill -name 'sihost' -force
Start-Sleep -s 5
$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
Start-Sleep -s 5

#Enable the ability to pin items again by disabling "LockedStartLayout"
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}

#Restart Explorer and delete the layout file
kill -name 'sihost' -force

Remove-Item $layoutFile

sleep 3

$wshell.SendKeys('^{ESCAPE}')

# remove some other apps

#backup app
dism /online /Get-Packages | Select-String "Microsoft-Windows-UserExperience-Desktop-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}


#steps recorder
dism /online /Get-Packages | Select-String "Microsoft-Windows-StepsRecorder-Package~31bf3856ad364e35~amd64~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}

#quick assist
dism /online /Get-Packages | Select-String "Microsoft-Windows-QuickAssist-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}

#hello face
dism /online /Get-Packages | Select-String "Microsoft-Windows-Hello-Face-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}

#lang
Disable-ScheduledTask -TaskPath \Microsoft\Windows\LanguageComponentsInstaller -TaskName Installation 
dism /online /Get-Packages | Select-String "Microsoft-Windows-LanguageFeatures-Speech-en-us-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}
dism /online /Get-Packages | Select-String "Microsoft-Windows-LanguageFeatures-Basic-en-us-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}
dism /online /Get-Packages | Select-String "Microsoft-Windows-LanguageFeatures-Handwriting-en-us-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}
dism /online /Get-Packages | Select-String "Microsoft-Windows-LanguageFeatures-OCR-en-us-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}
dism /online /Get-Packages | Select-String "Microsoft-Windows-LanguageFeatures-TextToSpeech-en-us-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}
Get-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessibility\*Speech*" | Remove-Item

#tablet pc math
dism /online /Get-Packages | Select-String "Microsoft-Windows-TabletPCMath-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}

#printing and fax
dism /online /Get-Packages | Select-String "Microsoft-Windows-Printing-PMCPPC-FoD-Package~31bf3856ad364e35~amd64~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}
dism /online /Get-Packages | Select-String "Microsoft-Windows-Printing-WFS-FoD-Package~31bf3856ad364e35~amd64~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}

#narrator
takeown.exe /f "C:\Windows\System32\Narrator.exe"
icacls.exe "C:\Windows\System32\Narrator.exe" /grant Administrators:F /T /C
Remove-Item -Force "C:\Windows\System32\Narrator.exe"
Remove-Item -Force "C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Narrator.lnk"
 

#disabling defender
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f

Write-Host "downloading necessary files..."
Invoke-RestMethod 'https://github.com/zoicware/Defender/archive/refs/heads/main.zip' -OutFile "C:\Defender.zip"
Expand-Archive "C:\Defender.zip" -DestinationPath "C:\"
Remove-Item "C:\Defender.zip"
Expand-Archive "C:\Defender-main\DisableDefender.zip" -DestinationPath "C:\"
Remove-Item  "C:\Defender-main" -Force -Recurse


#disables defender through gp edit
Write-Host "Disabling Defender with Group Policy" 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cache Maintenance'} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cleanup'} | Disable-ScheduledTask 
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Scheduled Scan'} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Verification'} | Disable-ScheduledTask
    

#apply gpedit tweaks

gpupdate /force


#searching c drive for bat file and power run and then running the bat file with power run
Write-Host "Disabling Services"

 $defender = Get-ChildItem -Path C:\ -Filter DisableDefend.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
 $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       $arguments = "-U:T -P:E -M:S "+"`"$defender`"" 
        Start-Process -FilePath $nsudo -ArgumentList $arguments -Wait

Remove-Item "C:\DisableDefender" -Force -Recurse

#adding photo viewer 
Reg.exe add "HKCU\SOFTWARE\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.cr2" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.dib" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.jfif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.jpe" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.jxr" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.tif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Classes\.wdp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /d "" /f


#setting ie to default browser
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -name ProgId IE.HTTP
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -name ProgId IE.HTTPS

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {

  Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f

  #you can guess what this does
Restart-Computer
 }

'No'{

Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f


}

}
