function Invoke-PC_Slow
{
  <#
    .SYNOPSIS
    Short Description
    .DESCRIPTION
    Detailed Description
    .EXAMPLE
    Invoke-PC_Slow
    explains how to use the command
    can be multiple lines
    .EXAMPLE
    Invoke-PC_Slow
    another example
    can have as many examples as you like
  #>
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
  
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}' /v 'LowerFilters' /t REG_MULTI_SZ /d 'fvevol\0iorate' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Services\rdyboost' /v 'Start' /t REG_DWORD /d '4' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Services\SysMain' /v 'Start' /t REG_DWORD /d '4' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters' /v 'EnablePrefetcher' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters' /v 'EnableSuperfetch' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt' /v 'GroupPolicyDisallowCaches' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt' /v 'AllowNewCachesByDefault' /t REG_DWORD /d '0' /f
  Disable-MMAgent -MemoryCompression
  Write-Output -InputObject 'Done'
  Start-Sleep -Seconds 1
  
  # Hide Windows Updates
  
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d 'hide:cortana;emailandaccounts;holographic-audio;privacy-automaticfiledownloads;privacy-feedback;windowsinsider;windowsupdate' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'IsWUHidden' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\taskkill.exe" /im explorer.exe /f
  Start-Process -FilePath explorer.exe
  Write-Output -InputObject 'Windows Updates is now hidden!'
  
  # Automatic drivers installing has disabled
  
  & "$env:windir\system32\reg.exe" add 'HKCU\Software\Policies\Microsoft\Windows\DriverSearching' /v 'DontPromptForWindowsUpdate' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\Software\Policies\Microsoft\Windows\DriverSearching' /v 'DontPromptForWindowsUpdate' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
  Write-Output -InputObject 'Automatic drivers installing has disabled successfuly!'
  
  # Force enable UAC, yes there is always a reason.
  
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableVirtualization' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableInstallerDetection' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'PromptOnSecureDesktop' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableLUA' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableSecureUIAPaths' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ConsentPromptBehaviorAdmin' /t REG_DWORD /d '5' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ValidateAdminCodeSignatures' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableUIADesktopToggle' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ConsentPromptBehaviorUser' /t REG_DWORD /d '3' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'FilterAdministratorToken' /t REG_DWORD /d '0' /f
  Write-Output -InputObject 'UAC has enabled successfuly. Please restart your PC.'
  
  # Force notifications to work, regardless of pay.
  
  & "$env:windir\system32\reg.exe" delete 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'NOC_GLOBAL_SETTING_TOASTS_ENABLED' /f
  & "$env:windir\system32\reg.exe" add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /f
  & "$env:windir\system32\reg.exe" add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications' /v 'ToastEnabled' /f
  & "$env:windir\system32\reg.exe" add 'HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications' /f
  & "$env:windir\system32\reg.exe" delete 'HKLM\Software\Microsoft\Windows\CurrentVersion\PushNotifications' /v 'ToastEnabled' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\Software\Microsoft\Windows\CurrentVersion\PushNotifications' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' /v 'NoToastApplicationNotification' /f
  & "$env:windir\system32\reg.exe" add 'HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' /v 'NoTileApplicationNotification' /f
  & "$env:windir\system32\reg.exe" add 'HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' /f
  
  & "$env:windir\system32\reg.exe" add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'IsNotificationsDisabled' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\taskkill.exe" /im explorer.exe /f
  Start-Process -FilePath explorer.exe
  Write-Output -InputObject 'Notifications has enabled successfuly.'
  
  # If you find that you are having trouble with Full Screen Optimizations, such as performance regression or input lag, we give you an opportunity to disable it.
  
  & "$env:windir\system32\reg.exe" add 'HKCU\System\GameConfigStore' /v 'GameDVR_FSEBehaviorMode' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\System\GameConfigStore' /v 'Win32_AutoGameModeDefaultProfile' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\System\GameConfigStore' /v 'Win32_GameModeRelatedProcesses' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\System\GameConfigStore' /v 'GameDVR_HonorUserFSEBehaviorMode' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\System\GameConfigStore' /v 'GameDVR_DXGIHonorFSEWindowsCompatible' /f
  & "$env:windir\system32\reg.exe" delete 'HKCU\System\GameConfigStore' /v 'GameDVR_EFSEFeatureFlags' /f
  
  & "$env:windir\system32\reg.exe" add 'HKU\.DEFAULT\System\GameConfigStore' /v 'GameDVR_FSEBehaviorMode' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\reg.exe" delete 'HKU\.DEFAULT\System\GameConfigStore' /v 'Win32_AutoGameModeDefaultProfile' /f
  & "$env:windir\system32\reg.exe" delete 'HKU\.DEFAULT\System\GameConfigStore' /v 'Win32_GameModeRelatedProcesses' /f
  & "$env:windir\system32\reg.exe" delete 'HKU\.DEFAULT\System\GameConfigStore' /v 'GameDVR_HonorUserFSEBehaviorMode' /f
  & "$env:windir\system32\reg.exe" delete 'HKU\.DEFAULT\System\GameConfigStore' /v 'GameDVR_DXGIHonorFSEWindowsCompatible' /f
  & "$env:windir\system32\reg.exe" delete 'HKU\.DEFAULT\System\GameConfigStore' /v 'GameDVR_EFSEFeatureFlags' /f
  Write-Output -InputObject 'FSO has enabled successfuly. Please restart your PC.'
  
  
  # VC Redist for all. Saves time + shit hassle.
  
  $ChkWget = Test-Path -Path "$env:ProgramW6432\WindowsApps\Microsoft.DesktopAppInstaller_1.18.2091.0_x64__8wekyb3d8bbwe"
  if ($ChkWget -eq $True) {
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.CLRTypesSQLServer.2019 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2005Redist-x64 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2005Redist-x86 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2008Redist-x64 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2008Redist-x86 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2010Redist-x64 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2010Redist-x86 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id=Microsoft.VC++2012Redist-x86 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id=Microsoft.VC++2012Redist-x64 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id=Microsoft.VC++2013Redist-x86 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id=Microsoft.VC++2013Redist-x64 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2015-2022Redist-x64 -e
    & "$env:LOCALAPPDATA\microsoft\windowsapps\winget.exe" install --id Microsoft.VC++2015-2022Redist-x86 -e  
  }
  else {
    Write-Output -InputObject "Winget wasn't found. Open Microsoft Store, go to Library, check for updates and update App Installer."
  }
  
  # Windows 11 specific
  #Disables the new right-click menu
  #Enables tabs in file explorer
  
  & "$env:windir\system32\reg.exe" add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /ve /t REG_SZ /d '' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\Software\Classes\CLSID' /v 'IsModernRCEnabled' /t REG_DWORD /d '0' /f
  & "$env:windir\system32\taskkill.exe" /im explorer.exe /f
  Start-Process -FilePath explorer.exe
  Write-Output -InputObject 'The new right-click menu has disabled successfuly'
  
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\1931258509' /v 'EnabledState' /t REG_DWORD /d '2' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\1931258509' /v 'EnabledStateOptions' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\248140940' /v 'EnabledState' /t REG_DWORD /d '2' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\248140940' /v 'EnabledStateOptions' /t REG_DWORD /d '1' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\2733408908' /v 'EnabledState' /t REG_DWORD /d '2' /f
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\4\2733408908' /v 'EnabledStateOptions' /t REG_DWORD /d '1' /f
  Write-Output -InputObject 'The new file explorer tabs has enabled successfuly, please restart your PC!'
  
  # powercfg, disable toerdo, inputpersonalist and platformclock edits
  
  & "$env:windir\system32\powercfg.cpl" /hibernate off >NUL
  & "$env:windir\system32\powercfg.cpl" -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >NUL
  & "$env:windir\system32\powercfg.cpl" -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 3ff9831b-6f80-4830-8178-736cd4229e7b >NUL
  & "$env:windir\system32\powercfg.cpl" -changename 3ff9831b-6f80-4830-8178-736cd4229e7b 'Ulta Performance' "Windows's Ultimate Performance with additional changes." >NUL
  & "$env:windir\system32\powercfg.cpl" -s 3ff9831b-6f80-4830-8178-736cd4229e7b >NUL
  & "$env:windir\system32\powercfg.cpl" -setacvalueindex scheme_current sub_processor PERFINCPOL 2 >NUL
  & "$env:windir\system32\powercfg.cpl" -setacvalueindex scheme_current sub_processor PERFDECPOL 1 >NUL
  & "$env:windir\system32\powercfg.cpl" -setacvalueindex scheme_current sub_processor PERFINCTHRESHOLD 10 >NUL
  & "$env:windir\system32\powercfg.cpl" -setacvalueindex scheme_current sub_processor PERFDECTHRESHOLD 8 >NUL
  & "$env:windir\system32\powercfg.cpl" /setactive scheme_current >NUL
  & "$env:windir\system32\netsh.exe" interface Teredo set state type=default >NUL
  & "$env:windir\system32\netsh.exe" interface Teredo set state servername=default >NUL
  #cmd.exe for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%a
  #cmd.exe /c "Set /a ram=%mem% + 1024000"
  & "$env:windir\system32\reg.exe" add 'HKLM\SYSTEM\CurrentControlSet\Control' /v 'SvcHostSplitThresholdInKB' /t REG_DWORD /d '%ram%' /f >NUL
  & "$env:windir\system32\reg.exe" delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' /f >NUL
  & "$env:windir\system32\reg.exe" add 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' /v 'AllowInputPersonalization' /t REG_DWORD /d '1' /f >NUL
  & "$env:windir\system32\bcdedit.exe" /deletevalue useplatformclock >NUL
  #bcdedit /set useplatformtick yes
  & "$env:windir\system32\bcdedit.exe" /set disabledynamictick yes >NUL
  & "$env:windir\system32\bcdedit.exe" /set bootmenupolicy Legacy >NUL
  & "$env:windir\system32\bcdedit.exe" /set lastknowngood yes >NUL
  & "$env:windir\system32\schtasks.exe" /change /tn '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem' /disable >NUL
  #if ($mem -gt 9000000) ( 
  #  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f >NUL
  #) else (
  # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >NUL
  #)
  & "$env:PSHome\powershell.exe" -NonInteractive -NoLogo -NoProfile Set-ProcessMitigation -Name vgc.exe -Enable CFG >NUL
  Invoke-Expression -Command Disable-MMAgent -Command -MemoryCompression
  ForEach($v in (Get-Command -Name 'Set-ProcessMitigation').Parameters['Disable'].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString().Replace(' ', '').Replace("`n", '')}
  Remove-Item -Path $PSCommandPath> -Path MC_PM.ps1
  & "$env:PSHome\powershell.exe" -windowstyle hidden -ExecutionPolicy Bypass -C "& './MC_PM.ps1'"
  
  
  
  
  
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
  Invoke-Command -ScriptBlock $null
  # NLA issue
  
  $domain = Get-WmiObject -Class win32_ntdomain | Select-Object -ExpandProperty DomainName
  $netca = Get-NetAdapter -Physical | Select-Object -ExpandProperty Name
  if ($netca -notcontains $domain) {
    Restart-Service -Name NlaSvc
  }  
  Else {
    Exit-PSHostProcess
  }
  
  & "$env:windir\system32\shutdown.exe" /r /f /t 120 /c 'shutting down to apply changes, canceling will have adverse affects.'
}

