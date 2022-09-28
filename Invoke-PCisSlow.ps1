Function Invoke-Slow_PC{
  <#
      .SYNOPSIS
      You are asking your GP "what do you do when you are sick"? But you don't provide symptoms.
      I mean, the answer can range from amputating an arm to just take a Neurofin+ and everything inbetween¯\_(ツ)_/¯
        
      .DESCRIPTION
      Just a few checks I usually do. In scenarios where the PC is in warranty or if the device is Windows 11. [yes I am a W11 shill].
      If this is for a home PC, check out https://github.com/Calvindd2f/Windows-10-11 . It disables shit like telemetry etc. Not suitable for prod workstations.
      .EXAMPLE
      (include all the magical ways to run a script... like right-clicking it, using start-process or icm. Or if you want to be a gamer copy the script path and pipe iex.
      .NOTES
      this shutsdown their machine after all is done.
  #>
}

#Requires -RunAsAdministrator

# Disabled Superfetch & Memory Compression.

  reg add "HKLM\SYSTEM\ControlSet001\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "fvevol\0iorate" /f
  reg add "HKLM\SYSTEM\ControlSet001\Services\rdyboost" /v "Start" /t REG_DWORD /d "4" /f
  reg add "HKLM\SYSTEM\ControlSet001\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f
  reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
  reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "GroupPolicyDisallowCaches" /t REG_DWORD /d "1" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "AllowNewCachesByDefault" /t REG_DWORD /d "0" /f
  Disable-MMAgent -MemoryCompression
  echo "Done"
  Sleep -Seconds 1

# Hide Windows Updates

  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:cortana;emailandaccounts;holographic-audio;privacy-automaticfiledownloads;privacy-feedback;windowsinsider;windowsupdate" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "IsWUHidden" /t REG_DWORD /d "1" /f
  taskkill /im explorer.exe /f
  start explorer.exe
  echo "Windows Updates is now hidden!"

# Automatic drivers installing has disabled

  reg add "HKCU\Software\Policies\Microsoft\Windows\DriverSearching" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d "1" /f
  reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d "1" /f
  reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
  echo "Automatic drivers installing has disabled successfuly!"

# Force enable UAC, yes there is always a reason.

  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "1" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "1" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "1" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "3" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f
  echo "UAC has enabled successfuly. Please restart your PC."

# Force notifications to work, regardless of pay.

  reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /f
  reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /f
  reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /f
  reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /f
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "0" /f
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /f
  reg delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /f
  reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /f
  reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /f
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /f
  reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /f
  reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /f
  reg delete "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /f
  reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /f
  reg delete "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /f
  reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /f

  reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "IsNotificationsDisabled" /t REG_DWORD /d "0" /f
  taskkill /im explorer.exe /f
  start explorer.exe
  echo "Notifications has enabled successfuly."

# If you find that you are having trouble with Full Screen Optimizations, such as performance regression or input lag, we give you an opportunity to disable it.

  reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f
  reg delete "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /f
  reg delete "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /f
  reg delete "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /f
  reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /f
  reg delete "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /f

  reg add "HKU\.DEFAULT\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f
  reg delete "HKU\.DEFAULT\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /f
  reg delete "HKU\.DEFAULT\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /f
  reg delete "HKU\.DEFAULT\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /f
  reg delete "HKU\.DEFAULT\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /f
  reg delete "HKU\.DEFAULT\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /f
  echo "FSO has enabled successfuly. Please restart your PC."


# VC Redist for all. Saves time + shit hassle.

$ChkWget = Test-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.18.2091.0_x64__8wekyb3d8bbwe"
if ($ChkWget -eq $True) {
  winget install --id Microsoft.CLRTypesSQLServer.2019 -e
  winget install --id Microsoft.VC++2005Redist-x64 -e
  winget install --id Microsoft.VC++2005Redist-x86 -e
  winget install --id Microsoft.VC++2008Redist-x64 -e
  winget install --id Microsoft.VC++2008Redist-x86 -e
  winget install --id Microsoft.VC++2010Redist-x64 -e
  winget install --id Microsoft.VC++2010Redist-x86 -e
  winget install --id=Microsoft.VC++2012Redist-x86 -e
  winget install --id=Microsoft.VC++2012Redist-x64 -e
  winget install --id=Microsoft.VC++2013Redist-x86 -e
  winget install --id=Microsoft.VC++2013Redist-x64 -e
  winget install --id Microsoft.VC++2015-2022Redist-x64 -e
  winget install --id Microsoft.VC++2015-2022Redist-x86 -e  
}
else {
  echo "Winget wasn't found. Open Microsoft Store, go to Library, check for updates and update App Installer."
}

# Windows 11 specific
  #Disables the new right-click menu
  #Enables tabs in file explorer

  reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f
  reg add "HKLM\Software\Classes\CLSID" /v "IsModernRCEnabled" /t REG_DWORD /d "0" /f
  taskkill /im explorer.exe /f
  start explorer.exe
  echo "The new right-click menu has disabled successfuly"

  reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\1931258509" /v "EnabledState" /t REG_DWORD /d "2" /f
  reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\1931258509" /v "EnabledStateOptions" /t REG_DWORD /d "1" /f
  reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\248140940" /v "EnabledState" /t REG_DWORD /d "2" /f
  reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\248140940" /v "EnabledStateOptions" /t REG_DWORD /d "1" /f
  reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\2733408908" /v "EnabledState" /t REG_DWORD /d "2" /f
  reg add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\2733408908" /v "EnabledStateOptions" /t REG_DWORD /d "1" /f
  echo "The new file explorer tabs has enabled successfuly, please restart your PC!"

# powercfg, disable toerdo, inputpersonalist and platformclock edits

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
  #bcdedit /set useplatformtick yes
  bcdedit /set disabledynamictick yes >NUL
  bcdedit /set bootmenupolicy Legacy >NUL
  bcdedit /set lastknowngood yes >NUL
  schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >NUL
  if %mem% gtr 9000000 ( 
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f >NUL
  ) else (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >NUL
  )
  powershell -NonInteractive -NoLogo -NoProfile Set-ProcessMitigation -Name vgc.exe -Enable CFG >NUL
  @echo Disable-MMAgent -MC; ForEach($v in (Get-Command -Name "Set-ProcessMitigation").Parameters["Disable"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString().Replace(" ", "").Replace("`n", "")}; rm $PSCommandPath> MC_PM.ps1
  powershell -windowstyle hidden -ExecutionPolicy Bypass -C "& './MC_PM.ps1'"





# Disable the .NET Telemetry on production servers and critical workstations
[Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT', '1', 'Machine')
[Environment]::SetEnvironmentVariable('MLDOTNET_CLI_TELEMETRY_OPTOUT', '1', 'Machine')

# Tweak the 1st run experience
[Environment]::SetEnvironmentVariable('DOTNET_SKIP_FIRST_TIME_EXPERIENCE', '1', 'Machine')



# Resync Clock

process
{
   $null = (& "$env:windir\system32\w32tm.exe" /resync /force)
}

# NLA issue

  $domain = gwmi win32_ntdomain | select DomainName
  $netca = Get-NetAdapter -Physical | Select-Object -Property Name
  if ($netca -notcontains $domain) {
  Restart-Service -Name NlaSvc
  }  
  Else {
  Exit-PSHostProcess
  }

shutdown /r /f /t 120 /c "shutting down to apply changes, canceling will have adverse affects."
