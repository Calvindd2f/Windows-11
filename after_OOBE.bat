@echo off
title CbOS_init
taskkill /IM explorer.exe /f >NUL
echo CbOS_init, do not close this window.
echo.
echo Make sure you did not select a character in the command prompt (a white rectangle)
echo which pauses the running process of the script. Press Enter and the script will continue.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f >NUL
::Check for UWP Apps updates
PowerShell -NonInteractive -NoLogo -NoProfile -Command "Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod" >NUL
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /v "" /t REG_SZ /f /d "" >NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f >NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >NUL
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >NUL
PowerShell -NonInteractive -NoLogo -NoProfile -Command "Disable-MMAgent -mc" >NUL
::Release v1.41.100 (Chromium 103.0.5060.134)
::https://github.com/brave/brave-browser/releases/download/v1.41.100/BraveBrowserStandaloneSetup.exe
if exist "C:\BraveBrowserStandaloneSetup.exe" (call "C:\BraveBrowserStandaloneSetup.exe" /silent /install)
if exist "C:\BraveBrowserStandaloneSetup.exe" (del "C:\BraveBrowserStandaloneSetup.exe") >NUL
::FileExplorerTabs
reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\1931258509" /v "EnabledState" /t REG_DWORD /d "2" /f >NUL
reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\1931258509" /v "EnabledStateOptions" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\248140940" /v "EnabledState" /t REG_DWORD /d "2" /f >NUL
reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\248140940" /v "EnabledStateOptions" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\2733408908" /v "EnabledState" /t REG_DWORD /d "2" /f >NUL
reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\2733408908" /v "EnabledStateOptions" /t REG_DWORD /d "1" /f >NUL
fsutil behavior set disableLastAccess 1 >NUL
fsutil behavior set disable8dot3 1 >NUL
net accounts /maxpwage:unlimited >NUL
powercfg /hibernate off >NUL
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >NUL
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 3ff9831b-6f80-4830-8178-736cd4229e7b >NUL
powercfg -changename 3ff9831b-6f80-4830-8178-736cd4229e7b "Ulta Performance" "Windows's Ultimate Performance with additional changes." >NUL
powercfg -s 3ff9831b-6f80-4830-8178-736cd4229e7b >NUL
powercfg -setacvalueindex scheme_current sub_processor PERFINCPOL 2 >NUL
powercfg -setacvalueindex scheme_current sub_processor PERFDECPOL 1 >NUL
powercfg -setacvalueindex scheme_current sub_processor PERFINCTHRESHOLD 10 >NUL
powercfg -setacvalueindex scheme_current sub_processor PERFDECTHRESHOLD 8 >NUL
powercfg /setactive scheme_current >NUL
netsh interface Teredo set state type=default >NUL
netsh interface Teredo set state servername=default >NUL
for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%a
set /a ram=%mem% + 1024000
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f >NUL
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /f >NUL
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "1" /f >NUL
bcdedit /deletevalue useplatformclock >NUL
::bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes >NUL
bcdedit /set bootmenupolicy Legacy >NUL
bcdedit /set lastknowngood yes >NUL
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >NUL
wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /e:false >NUL
wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /e:false >NUL
wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /e:false >NUL
if %mem% gtr 9000000 ( 
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f >NUL
) else (
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >NUL
)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f >NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ctfmon" /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f >NUL
:: Fixes the Internet Explorer error which says "Unable to launch Microsoft Edge"
reg add "HKCR\MSEdgeHTM" /ve /t REG_SZ /d "Brave HTML Document" /f >NUL
reg add "HKCR\MSEdgeHTM" /v "AppUserModelId" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgeHTM\Application" /v "AppUserModelId" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgeHTM\Application" /v "ApplicationIcon" /t REG_SZ /d "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe,0" /f >NUL
reg add "HKCR\MSEdgeHTM\Application" /v "ApplicationName" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgeHTM\Application" /v "ApplicationDescription" /t REG_SZ /d "Access the Internet" /f >NUL
reg add "HKCR\MSEdgeHTM\Application" /v "ApplicationCompany" /t REG_SZ /d "Brave Software Inc" /f >NUL
reg add "HKCR\MSEdgeHTM\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe,0" /f >NUL
reg add "HKCR\MSEdgeHTM\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe\" --single-argument %%1" /f >NUL
reg add "HKCR\MSEdgeHTM\shell\runas\command" /ve /t REG_SZ /d "\"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe\" --do-not-de-elevate --single-argument %%1" /f >NUL
reg add "HKCR\MSEdgeMHT" /ve /t REG_SZ /d "Brave MHT Document" /f >NUL
reg add "HKCR\MSEdgeMHT" /v "AppUserModelId" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgeMHT\Application" /v "AppUserModelId" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgeMHT\Application" /v "ApplicationIcon" /t REG_SZ /d "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe,0" /f >NUL
reg add "HKCR\MSEdgeMHT\Application" /v "ApplicationName" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgeMHT\Application" /v "ApplicationDescription" /t REG_SZ /d "Access the Internet" /f >NUL
reg add "HKCR\MSEdgeMHT\Application" /v "ApplicationCompany" /t REG_SZ /d "Brave Software Inc" /f >NUL
reg add "HKCR\MSEdgeMHT\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe,0" /f >NUL
reg add "HKCR\MSEdgeMHT\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe\" --single-argument %%1" /f >NUL
reg add "HKCR\MSEdgeMHT\shell\runas\command" /ve /t REG_SZ /d "\"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe\" --do-not-de-elevate --single-argument %%1" /f >NUL
reg add "HKCR\MSEdgePDF" /ve /t REG_SZ /d "Brave PDF Document" /f >NUL
reg add "HKCR\MSEdgePDF" /v "AppUserModelId" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgePDF\Application" /v "AppUserModelId" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgePDF\Application" /v "ApplicationIcon" /t REG_SZ /d "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe,0" /f >NUL
reg add "HKCR\MSEdgePDF\Application" /v "ApplicationName" /t REG_SZ /d "Brave" /f >NUL
reg add "HKCR\MSEdgePDF\Application" /v "ApplicationDescription" /t REG_SZ /d "Access the Internet" /f >NUL
reg add "HKCR\MSEdgePDF\Application" /v "ApplicationCompany" /t REG_SZ /d "Brave Software Inc" /f >NUL
reg add "HKCR\MSEdgePDF\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe,0" /f >NUL
reg add "HKCR\MSEdgePDF\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe\" --single-argument %%1" /f >NUL
reg add "HKCR\MSEdgePDF\shell\runas\command" /ve /t REG_SZ /d "\"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe\" --do-not-de-elevate --single-argument %%1" /f >NUL
powershell -NonInteractive -NoLogo -NoProfile Set-ProcessMitigation -Name vgc.exe -Enable CFG >NUL
@echo Disable-MMAgent -MC; ForEach($v in (Get-Command -Name "Set-ProcessMitigation").Parameters["Disable"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString().Replace(" ", "").Replace("`n", "")}; rm $PSCommandPath> MC_PM.ps1
powershell -windowstyle hidden -ExecutionPolicy Bypass -C "& './MC_PM.ps1'"
::EnableUAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "1" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "3" /f >NUL
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f >NUL
shutdown /r /f /t 5 /c "CbOS is ready, rebooting..."
DEL "%~f0"
exit
