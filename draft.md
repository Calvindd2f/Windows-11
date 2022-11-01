# Remove windows communication apps {mail , calender etc} forcefully incentivise using outlook.

    Get-AppxPackage -allusers *windowscommunicationsapps* | Remove-AppxPackage
