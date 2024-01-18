do
 {
 	$selection = Read-Host "Please make a selection
 	1 - Change RDP any port from 40000 to 65536 (TCP)
	2 - Change RDP port to  3389 (TCP)
	3 - Check RDP port

 	4 - Disable UAC
 	5 - Disable UDP
 	6 - Disable SmartScreen

 	7 - Create page file 1 Gb
 	8 - Create page file 2 Gb

	9 - Disable end time password
	10 - Black screen Windows 2019 (solution)

	11 - Localization RUS VPS 2012
	12 - Localization RUS DS 2012
	13 - Localization RUS VPS 2016
	14 - Localization RUS VPS 2019

	15 - Disable update 2012, 2016, 2019
	16 - Enable update 2012, 2016, 2019

	17 - Completely disable Windows Firewall (not recommended)
	18 - Enable Windows Firewall

	19 - WINDOWS ACTIVATION 2012
	20 - WINDOWS ACTIVATION 2016
	21 - WINDOWS ACTIVATION 2019
	22 - WINDOWS ACTIVATION 2022

	23 - Verify presence .NET Framework
	24 - Install .NET Framework 3.5
	25 - Install .NET Framework 4.5
	26 - Install .NET Framework 4.8

	27 - Install Google Chrome
	28 - Install 7zip
	29 - Install IPBan (2016, 2019)
	30 - IPBan STOP/demand
	31 - IPBan START/delayed-auto
	32 - Reset rules IPBan_Block_0

	33 - Disable IExplorer enhanced security
	34 - Enable ICMP packets
	35 - Disable ICMP packets
	36 - RDP session timeout
	37 - Increase TCP Connections

	38 - Optimisation at one click
	39 - Check Update Status
 	40 - Pause


	000 - Reboot PC
 	q - exit
 	"
 	switch ($selection)
 	{
     	  '1' {
         	'Change RDP any port from 40000 to 65536 (TCP)'
         	$port=Read-Host "Enter port";

			While ($port -ne "exit" -And $port -ne "quit" -And $port -ne "q"  -And $port -ne "x") {

			  try
			  {
				  $port = [convert]::ToUInt32($port);

				  if ($port -lt 40000 -Or $port -gt 65536)
				{
				  echo "error port";
				}
				  else
				{
				  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "PortNumber" /t REG_DWORD /d $port /f; netsh advfirewall firewall add rule name="RDP-Port" protocol=TCP localport=$port action=allow dir=IN; net stop TermService /y; net start TermService;

				  echo "set port $port";

				  break;
				}
			  }
				  catch
			  {
				  echo "error converting to int";
			  }

			  $port = Read-Host "Enter port";
			}
     	} '2' {
         	'Change RDP port to  3389 (TCP)'
         	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "PortNumber" /t REG_DWORD /d 3389 /f; netsh advfirewall firewall add rule name="RDP-Port" protocol=TCP localport=3389 action=allow dir=IN; net stop TermService /y; net start TermService;
     	} '3' {
         	'Check RDP port'
         	get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\'-name portnumber ;
     	} '4' {
         	'Disable UAC'
         	reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f;
     	} '5' {
         	'Disable UDP'
         	reg add "HKLM\software\policies\microsoft\windows nt\Terminal Services\Client" /v fClientDisableUDP /d 1 /t REG_DWORD; pause; net stop TermService /y; net start TermService;
     	} '6' {
     		'Disable SmartScreen'
     		reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer /v SmartScreenEnabled /f /t REG_SZ /d "Off";
     	} '7' {
     		'Create page file 1 Gb'
     		reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "C:\pagefile.sys 1024 1024" /f;
     	} '8' {
     		'Create page file 2 Gb'
     		reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "C:\pagefile.sys 2048 2048" /f;
     	} '9' {
     		'Disable end time password'
     		cmd /c "WMIC USERACCOUNT WHERE Name='Administrator' SET PasswordExpires=FALSE";
     	} '10' {
     		'Black screen Windows 2019 (solution)'
     		reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fEnableWddmDriver" /t REG_DWORD /d 0 /f; New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Terminal Server Client" -Name UseURCP -PropertyType DWord -Value 0;
     	} '11' {
     		'Localization RUS VPS 2012'
     		Set-Culture ru-RU; Set-WinUILanguageOverride -Language ru-RU; $list = Get-WinUserLanguageList; $list.Add("ru-RU"); Set-WinUserLanguageList $list -Force; Set-WinHomeLocation -GeoId 203; Set-WinSystemLocale -SystemLocale ru-RU;
     	} '12' {
     		'Localization RUS DS 2012'
     		$destination = 'c:\lp_ru.cab'; $source = new-object System.Net.WebClient; $source.DownloadFile("https://scripts-eu.had.su/windows_ru_lang/lp_12_ru.cab", $destination); cmd.exe /c "Cscript %WinDir%\System32\SCregEdit.wsf /AU 1"; Start-Process -NoNewWindow -FilePath "C:\windows\system32\net" -ArgumentList "stop","wuauserv"; lpksetup /i ru-RU /r /s /p $destination; Start-Sleep -Seconds 5; While (!(Get-Process TiWorker)) { Start-Sleep -Seconds 1 }; While ((Get-Process TiWorker)) { Start-Sleep -Seconds 1 }; Set-Culture ru-RU;  Set-WinUILanguageOverride -Language ru-RU; $list = Get-WinUserLanguageList; $list.Add("ru-RU"); Set-WinUserLanguageList $list -Force; Set-WinHomeLocation -GeoId 203; Set-WinSystemLocale -SystemLocale ru-RU; Remove-Item -Path $destination -Force; $wsh = New-Object -ComObject Wscript.Shell; $wsh.Popup("Language Pack Installed");
     	} '13' {
     		'Localization RUS VPS 2016'
     		$destination = 'c:\lp_ru.cab'; $source = new-object System.Net.WebClient; $source.DownloadFile("https://scripts-eu.had.su/windows_ru_lang/lp_16_ru.cab", $destination); cmd.exe /c "Cscript %WinDir%\System32\SCregEdit.wsf /AU 1"; Start-Process -NoNewWindow -FilePath "C:\windows\system32\net" -ArgumentList "stop","wuauserv"; lpksetup /i ru-RU /r /s /p $destination; Start-Sleep -Seconds 5; While (!(Get-Process TiWorker)) { Start-Sleep -Seconds 1 }; While ((Get-Process TiWorker)) { Start-Sleep -Seconds 1 }; Set-Culture ru-RU;  Set-WinUILanguageOverride -Language ru-RU; $list = Get-WinUserLanguageList; $list.Add("ru-RU"); Set-WinUserLanguageList $list -Force; Set-WinHomeLocation -GeoId 203; Set-WinSystemLocale -SystemLocale ru-RU;Remove-Item -Path $destination -Force; $wsh = New-Object -ComObject Wscript.Shell; $wsh.Popup("Language Pack Installed");
     	} '14' {
     		'Localization RUS VPS 2019'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$destination = 'c:\lp_ru.cab'
Invoke-WebRequest -Uri 'https://scripts-eu.had.su/windows_ru_lang/lp_19_ru.cab' -OutFile $destination
cmd.exe /c 'Cscript %WinDir%\System32\SCregEdit.wsf /AU 1'
Start-Process -FilePath 'lpksetup' -ArgumentList "/i ru-RU /r /s /p $destination" -Wait

Set-Culture ru-RU
Set-WinUILanguageOverride -Language ru-RU
$list = Get-WinUserLanguageList
$list.Add('ru-RU')
Set-WinUserLanguageList $list -Force
Set-WinHomeLocation -GeoId 203
Set-WinSystemLocale -SystemLocale ru-RU
$LanguageTag = 'ru-RU'
$LangList = New-WinUserLanguageList $LanguageTag
$LangList.Add($LanguageTag)
Set-WinUILanguageOverride -Language $LanguageTag
$LangList[0].InputMethodTips.Add("$LanguageTag:00000419")
Set-WinUserLanguageList $LangList -Force

     	} '15' {
     		'Disable update 2012, 2016, 2019'
If (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1;
     	} '16' {
     		'Enable update 2012, 2016, 2019'
If (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0;
     	} '17' {
     		'Completely disable Windows Firewall'
     		Get-NetFirewallProfile | Set-NetFirewallProfile -enabled false;
     	} '18' {
     		'Enable Windows Firewall'
     		Get-NetFirewallProfile | Set-NetFirewallProfile -enabled true;
     	} '19' {
     		'WINDOWS ACTIVATION 2012'
     		cscript.exe C:\Windows\system32\slmgr.vbs /upk; cscript.exe C:\Windows\system32\slmgr.vbs /ipk D2N9P-3P6X9-2R39C-7RTCD-MDVJX; cscript.exe C:\Windows\system32\slmgr.vbs /skms kms.had.su; cscript.exe C:\Windows\system32\slmgr.vbs /ato; cscript.exe C:\Windows\system32\slmgr.vbs /dlv;
     	} '20' {
     		'WINDOWS ACTIVATION 2016'
     		cscript.exe C:\Windows\system32\slmgr.vbs /upk; cscript.exe C:\Windows\system32\slmgr.vbs /ipk WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY; cscript.exe C:\Windows\system32\slmgr.vbs /skms kms.had.su; cscript.exe C:\Windows\system32\slmgr.vbs /ato; cscript.exe C:\Windows\system32\slmgr.vbs /dlv;
     	} '21' {
     		'WINDOWS ACTIVATION 2019'
     		cscript.exe C:\Windows\system32\slmgr.vbs /upk; cscript.exe C:\Windows\system32\slmgr.vbs /ipk N69G4-B89J2-4G8F4-WWYCC-J464C; cscript.exe C:\Windows\system32\slmgr.vbs /skms kms.had.su; cscript.exe C:\Windows\system32\slmgr.vbs /ato; cscript.exe C:\Windows\system32\slmgr.vbs /dlv;
     	} '22' {
     		'WINDOWS ACTIVATION 2022'
     		net start sppsvc; cd C:\Windows\system32; cscript.exe slmgr.vbs /upk; cscript.exe slmgr.vbs /ipk VDYBN-27WPP-V4HQT-9VMD4-VMK7H; cscript.exe slmgr.vbs /skms kms.had.su; cscript.exe; slmgr.vbs /ato; cscript.exe slmgr.vbs /dlv;
     	} '23' {
     		'Verify presence .NET Framework'
     		Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -name Version -EA 0 | Where { $_.PSChildName -match '^(?!S)\p{L}'} | Select PSChildName, Version;
     	} '24' {
     		'Install .NET Framework 3.5'
$script = {
    $ProgressPreference = 'SilentlyContinue' # Отключение вывода прогресса
    Import-Module ServerManager
    Install-WindowsFeature NET-Framework-Core
}

$base64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script.ToString()))
Start-Process -NoNewWindow powershell -ArgumentList "-encodedCommand $base64"
     	} '25' {
     		'Install .NET Framework 4.5'
$script = {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = 'https://download.microsoft.com/download/B/A/4/BA4A7E71-2906-4B2D-A0E1-80CF16844F5F/dotNetFx45_Full_setup.exe'
    $output = "$Env:Temp\Net4.5.exe"
    $webclient = New-Object System.Net.WebClient
    $webclient.DownloadFile($url, $output)
    Start-Process -FilePath $output -ArgumentList '/q /norestart' -Wait
}

$base64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script.ToString()))
Start-Process -NoNewWindow powershell -ArgumentList "-encodedCommand $base64"
     	} '26' {
     		'Install .NET Framework 4.8'
$script = {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = 'https://go.microsoft.com/fwlink/?linkid=2088631'
    $output = "$Env:Temp\Net4.8.exe"
    $webclient = New-Object System.Net.WebClient
    $webclient.DownloadFile($url, $output)
    Start-Process -FilePath $output -ArgumentList '/q /norestart' -Wait
}

$base64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script.ToString()))
Start-Process -NoNewWindow powershell -ArgumentList "-encodedCommand $base64"
     	} '27' {
     		'Install Google Chrome'
$LocalTempDir = $env:TEMP
$ChromeInstaller = "ChromeInstaller.exe"
$InstallerPath = Join-Path -Path $LocalTempDir -ChildPath $ChromeInstaller

$ScriptBlock = {
    param ($InstallerPath, $DownloadURL)
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadURL, $InstallerPath)
    Start-Process -FilePath $InstallerPath -ArgumentList "/silent", "/install" -WindowStyle Hidden
    Start-Sleep -Seconds 20
    Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Start Installing Google Chrome..."
$DownloadURL = 'http://dl.google.com/chrome/install/375.126/chrome_installer.exe'
Start-Job -ScriptBlock $ScriptBlock -ArgumentList $InstallerPath, $DownloadURL

     	} '28' {
     		'Install 7zip'
$LocalTempDir=$env:TEMP
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

$dlurl = 'https://7-zip.org/' + (
    Invoke-WebRequest -UseBasicParsing -Uri 'https://7-zip.org/' |
    Select-Object -ExpandProperty Links |
    Where-Object {
        ($_.outerHTML -match 'Download') -and
        ($_.href -like "a/*") -and
        ($_.href -like "*-x64.exe")
    } |
    Select-Object -First 1 |
    Select-Object -ExpandProperty href
)

$Installer="7zipInstaller.exe"

(new-object System.Net.WebClient).DownloadFile($dlurl, "$LocalTempDir\$Installer")

Write-Host "Install 7-Zip in progress ..."
& "$LocalTempDir\$Installer" /S

     	} '29' {
            'Install IPBan (2016, 2019)'
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Windows/Scripts/install_latest.ps1'))
        } '30' {
     		'IPBan STOP/demand'
     		sc.exe stop IPBAN; sc.exe config IPBAN start=demand;
     	} '31' {
     		'IPBan START/delayed-auto'
     		sc.exe start IPBAN; sc.exe config IPBAN start=delayed-auto;
     	} '32' {
     		'Reset rules IPBan_Block_0'
     		Get-NetFirewallrule -DisplayName 'IPBan_Block_0'|Set-NetFirewallRule -RemoteAddress 123.123.123.123; Get-NetFirewallrule -DisplayName 'IPBan_EmergingThreats_0'|Set-NetFirewallRule -RemoteAddress 123.123.123.123; Get-NetFirewallrule -DisplayName 'IPBan_EmergingThreats_1000'|Set-NetFirewallRule -RemoteAddress 123.123.123.123;
     	} '33' {
     		'Disable IExplorer enhanced security'
     		function Disable-IEESC { $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"; $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"; Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0; 	Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0; Stop-Process -Name Explorer; Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green }; Disable-IEESC;
     	} '34' {
     		'Enable ICMP packets'
     		Enable-NetFirewallRule -DisplayName "Virtual Machine Monitoring (Echo Request - ICMPv4-In)";
     	} '35' {
     		'Disable ICMP packets'
     		Disable-NetFirewallRule -DisplayName "Virtual Machine Monitoring (Echo Request - ICMPv4-In)";
     	} '36' {
     		'RDP session timeout'
     		reg add "HKLM\software\policies\microsoft\windows nt\Terminal Services" /v MaxIdleTime /d 0 /t REG_DWORD;  pause; net stop TermService /y; net start TermService /y; exit;
     	} '37' {
     		'Increase TCP Connections'
     		reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v TcpNumConnections /d 0 /t REG_DWORD;
     	} '38' {
     		'Optimisation at one click'
			reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "PortNumber" /t REG_DWORD /d 55444 /f; netsh advfirewall firewall add rule name="RDP-Port" protocol=TCP localport=55444 action=allow dir=IN; reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f; reg add "HKLM\software\policies\microsoft\windows nt\Terminal Services\Client" /v fClientDisableUDP /d 1 /t REG_DWORD; reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "C:\pagefile.sys 2048 2048" /f; cmd /c "WMIC USERACCOUNT WHERE Name='Administrator' SET PasswordExpires=FALSE"; If (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force}; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1; pause; net stop TermService /y; net start TermService /y;
     	} '39' {
     	'Check Update Status'
     		$autoUpdateValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue

            if ($autoUpdateValue) {
                if ($autoUpdateValue.NoAutoUpdate -eq 0) {
                    Write-Output "Automatic Updates is enabled."
                } elseif ($autoUpdateValue.NoAutoUpdate -eq 1) {
                    Write-Output "Automatic Updates is disabled."
                } else {
                    Write-Output "Unexpected value for NoAutoUpdate."
                }
            } else {
                Write-Output "Automatic Updates configuration might not be set via policies or an error occurred."
            }
     	} '40' {
pause;


     	} '000' {
     		'Reboot PC'
            pause; Restart-Computer;
     	}
 	    }
 	pause
}
 until ($selection -eq 'q')
