  # Windows 11

*Apply these on a new install. Ideally, it should be during the deployment.*


- Revert to Windows 10 Context Menu.

      reg add HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32 /ve /d "" /f

- Revert Context Menu Change.

      reg.exe delete “HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}” /f
      
- Reset MS Store

      wsreset -i 
