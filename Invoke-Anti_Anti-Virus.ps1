# Placeholder
$computername=$env:computername
$AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

# To Do

#Invoke-Anti_AntiVirus
#https://github.com/Calvindd2f/Windows-10-11/blob/main/Invoke-Anti_Anti-Virus.ps1

#$computername=$env:computername
#$AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $env:computername
















































































<#
$computerList = "localhost", "localhost"
$filter = "antivirus"

$results = @()
foreach($computerName in $computerList) {

    $hive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $computerName)
    $regPathList = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                   "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    foreach($regPath in $regPathList) {
        if($key = $hive.OpenSubKey($regPath)) {
            if($subkeyNames = $key.GetSubKeyNames()) {
                foreach($subkeyName in $subkeyNames) {
                    $productKey = $key.OpenSubKey($subkeyName)
                    $productName = $productKey.GetValue("DisplayName")
                    $productVersion = $productKey.GetValue("DisplayVersion")
                    $productComments = $productKey.GetValue("Comments")
                    if(($productName -match $filter) -or ($productComments -match $filter)) {
                        $resultObj = [PSCustomObject]@{
                            Host = $computerName
                            Product = $productName
                            Version = $productVersion
                            Comments = $productComments
                        }
                        $results += $resultObj
                    }
                }
            }
        }
        $key.Close()
    }
}

$results | ft -au
#>
