$timestamp = Get-Date -Format "yyyy-MM-dd HH-mm"

Start-Transcript -Path "C:\VeeamSecurityScript\$timestamp log.txt"


Write-Host "   _____ _____   _____ " -ForegroundColor Red
Write-Host "  / ____|  __ \ / ____|" -ForegroundColor Red
Write-Host " | (___ | |__) | (___  " -ForegroundColor Red
Write-Host "  \___ \|  _  / \___ \ " -ForegroundColor Red
Write-Host "  ____) | | \ \ ____) |" -ForegroundColor Red
Write-Host " |_____/|_|  \_\_____/ " -ForegroundColor Red
Write-Host " "               
                     


Write-Host "======== VEEAM SECURITY AND COMPLIANCE ========" -ForegroundColor Green
Write-Host " "   
Write-Host "TAKE NOTE! This script WILL return errors when it cannot find registry keys. This is expected. Just press Y to create any keys that it cannot find, or press H to skip it."
Write-Host " "   
Write-Host " "  

# Warn about running before Veeam installed
Write-Host "[GENERAL][WARN] If you run this utility before installing Veeam, you will have issues installing Veeam later."  -ForegroundColor Yellow
Write-Host "[GENERAL][WARN] You may have issues with apps that use WinRM or WinScriptHost (Server Manager, Veeam Installer, etc.)"  -ForegroundColor Yellow
try {
    Write-Warning "Continue?" -WarningAction Inquire
    Write-Host "[GENERAL][CONFIRM] Proceeding..." -ForegroundColor Green
}
catch {
    Write-Error "[GENERAL][FATAL] You said no. Do what you need to do, then come back."
    exit 1
}


# Remote Desktop Services
Write-Host "[RDS][INFO] Checking RDS Service Status..." -ForegroundColor Cyan
if ((Get-Service -Name "TermService").StartType -eq "Disabled") {
    Write-Host "[RDS][SUCCESS] RDS is disabled." -ForegroundColor Green
}
else {
    Write-Host "[RDS][WARN] RDS (Remote Desktop Services) is not disabled."  -ForegroundColor Yellow
    Write-Host "[RDS][WARN] If you use RDP on this machine, turning this off will brick your connection." -ForegroundColor Yellow
    try {
        Write-Warning "Disable Service?" -WarningAction Inquire
        try {
            Stop-Service -Name "TermService" -Force
            Set-Service -Name "TermService" -StartupType Disabled
            Write-Host "[RDS][SUCCESS] RDS has been disabled." -ForegroundColor Green
        }
        catch {
            Write-Error "[RDS][ERROR] RDS could not be disabled."
        }
        
    }
    catch {
        Write-Host "[RDS][WARN] RDS will not be disabled." -ForegroundColor Yellow
    }
}

# Remote Registry
Write-Host "[REG][INFO] Checking RemoteRegistry Service Status..." -ForegroundColor Cyan
if ((Get-Service -Name "RemoteRegistry").StartType -eq "Disabled") {
    Write-Host "[REG][SUCCESS] Remote Registry is disabled." -ForegroundColor Green
}
else {
    Write-Host "[REG][WARN] Remote Registry is not disabled." -ForegroundColor Yellow
    try {
        Write-Warning "Disable Service?" -WarningAction Inquire
        try {
            Stop-Service -Name "RemoteRegistry" -Force
            Set-Service -Name "RemoteRegistry" -StartupType Disabled
            Write-Host "[REG][SUCCESS] Remote Registry has been disabled." -ForegroundColor Green
        }
        catch {
            Write-Error "[REG][ERROR] Remote Registry could not be disabled."
        }
        
    }
    catch {
        Write-Host "[REG][WARN] Remote Registry will not be disabled." -ForegroundColor Yellow
    }
}

# Windows Remote Management
Write-Host "[WINRM][INFO] Checking WinRM Service Status..." -ForegroundColor Cyan
if ((Get-Service -Name "WinRM").StartType -eq "Disabled") {
    Write-Host "[WINRM][SUCCESS] Windows Remote Management (WINRM) is disabled." -ForegroundColor Green
}
else {
    Write-Host "[WINRM][WARN] Windows Remote Management (WINRM) is not disabled." -ForegroundColor Yellow
    try {
        Write-Warning "Disable Service?" -WarningAction Inquire
        try {
            Stop-Service -Name "WinRM" -Force
            Set-Service -Name "WinRM" -StartupType Disabled
            Write-Host "[WINRM][SUCCESS] Windows Remote Management (WINRM) has been disabled." -ForegroundColor Green
        }
        catch {
            Write-Error "[WINRM][ERROR] Windows Remote Management (WINRM) could not be disabled."
        }
        
    }
    catch {
        Write-Host "[WINRM][WARN] Windows Remote Management (WINRM) will not be disabled." -ForegroundColor Yellow
    }
}

# Windows Firewall
Write-Host "[FWL][INFO] Checking Firewalls..." -ForegroundColor Cyan
foreach ($profile in (Get-NetFirewallProfile)) {
    $profilename = $profile.Name
    if ($profile.Enabled) {
        Write-Host "[FWL][SUCCESS] Firewall $profilename is enabled already." -ForegroundColor Green
    }
    else {
        Write-Host "[FWL][WARN] Firewall $profilename is not enabled." -ForegroundColor Yellow
        try {
            Write-Warning "Enable Firewall?" -WarningAction Inquire
            try {
                Get-NetFirewallProfile -Name $profilename | Set-NetFirewallProfile -Enabled True
                Write-Host "[FWL][SUCCESS] Firewall $profilename is active." -ForegroundColor Green
            }
            catch {
                Write-Error "[FWL][ERROR] Firewall $profilename couldn't be enabled."
            }
            
        }
        catch {
            Write-Host "[FWL][WARN] Firewall $profilename will not be enabled." -ForegroundColor Yellow
        }
    }
}

# WDigest
Write-Host "[WDIG][INFO] Checking WinDigest Status..." -ForegroundColor Cyan
$wdigest = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" | Select-Object -expand "UseLogonCredential"
if ($wdigest -eq 0) {
    Write-Host "[WDIG][SUCCESS] WDigest is disabled." -ForegroundColor Green
}
else {
    Write-Host "[WDIG][WARN] WDigest is not disabled." -ForegroundColor Yellow
    try {
        Write-Warning "Disable WDigest?" -WarningAction Inquire
        reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
        Write-Host "[WDIG][SUCCESS] WDigest was disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[WDIG][WARN] WDigest won't be disabled." -ForegroundColor Yellow
    }
}

# WinHTTP
Write-Host "[WHTTP][INFO] Checking WinHTTP Web Proxy Auto-Discovery Status..." -ForegroundColor Cyan
$whttp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" | Select-Object -expand "DisableWpad"
if ($whttp -eq 1) {
    Write-Host "[WHTTP][SUCCESS] WinHTTP Web Proxy Auto-Discovery is disabled." -ForegroundColor Green
}
else {
    Write-Host "[WHTTP][WARN] WinHTTP Web Proxy Auto-Discovery is not disabled." -ForegroundColor Yellow
    try {
        Write-Warning "Disable WinHTTP Web Proxy Auto-Discovery?" -WarningAction Inquire
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DisableWpad /t REG_DWORD /d 1 /f
        Write-Host "[WHTTP][SUCCESS] WinHTTP Web Proxy Auto-Discovery was disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[WHTTP][WARN] WinHTTP Web Proxy Auto-Discovery won't be disabled." -ForegroundColor Yellow
    }
}

# SSLTLS
$keystocheck = @(
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
        "value" = "DisabledByDefault"
        "data"  = 1
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
        "value" = "Enabled"
        "data"  = 0
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
        "value" = "Enabled"
        "data"  = 0
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
        "value" = "Enabled"
        "data"  = 0
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
        "value" = "Enabled"
        "data"  = 0
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
        "value" = "Enabled"
        "data"  = 0
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
        "value" = "Enabled"
        "data"  = 0
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
        "value" = "Enabled"
        "data"  = 0
    },
    @{
        "name"  = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
        "value" = "Enabled"
        "data"  = 0
    }
) 
Write-Host "[SSLTLS][INFO] Checking SSL/TLS Status..." -ForegroundColor Cyan
foreach ($record in $keystocheck) {
    $recordorig = $record.name
    $recordcheck = $record.name -replace "HKLM\\", "HKLM:\\"
    $recordcurrentval = Get-ItemProperty -Path $recordcheck -Name $record.value | Select-Object -expand $record.value
    if ($recordcurrentval -eq $record.data) {
        Write-Host "[SSLTLS][SUCCESS] Key $recordcheck is already expected value." -ForegroundColor Green
    }
    else {
        try {
            Write-Host "[SSLTLS][WARN] Key $recordcheck is not expected value." -ForegroundColor Yellow
            Write-Warning "Set value of to expected?" -WarningAction Inquire
            reg add "$recordorig" /v $record.value /t REG_DWORD /d $record.data /f
            Write-Host "[SSLTLS][SUCCESS] Value changed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "[SSLTLS][WARN] Value won't be changed." -ForegroundColor Yellow
        }
    }
}

# Windows Script Host
Write-Host "[WSH][INFO] Checking Windows Script Host Status..." -ForegroundColor Cyan
$wsh = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" | Select-Object -expand "Enabled"
if ($wsh -eq 0) {
    Write-Host "[WSH][SUCCESS] Windows Script Host is disabled." -ForegroundColor Green
}
else {
    Write-Host "[WSH][WARN] Windows Script Host is not disabled." -ForegroundColor Yellow
    try {
        Write-Warning "Disable Windows Script Host?" -WarningAction Inquire
        reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f
        Write-Host "[WSH][SUCCESS] Windows Script Host was disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[WSH][WARN] Windows Script Host won't be disabled." -ForegroundColor Yellow
    }
}

# SMB1
Write-Host "[SMB1][INFO] Checking SMBv1 Status..." -ForegroundColor Cyan
$smb1 = Get-SmbServerConfiguration | Select-Object -Expand EnableSMB1Protocol
if ($smb1 -eq $false) {
    Write-Host "[SMB1][SUCCESS] SMBv1 is disabled." -ForegroundColor Green
}
else {
    Write-Host "[SMB1][WARN] SMBv1 is not disabled." -ForegroundColor Yellow
    try {
        Write-Warning "Disable SMBv1?" -WarningAction Inquire
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
        Write-Host "[SMB1][SUCCESS] SMBv1 was disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[SMB1][WARN] SMBv1 won't be disabled." -ForegroundColor Yellow
    }
}

# Link-Local Multicast Name Resolution
Write-Host "[LLMNR][INFO] Link-Local Multicast Name Resolution Status..." -ForegroundColor Cyan
$llm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMultiCast" | Select-Object -expand "EnableMultiCast"
if ($llm -eq 0) {
    Write-Host "[LLMNR][SUCCESS] Link-Local Multicast Name Resolution is disabled." -ForegroundColor Green
}
else {
    Write-Host "[LLMNR][WARN] Link-Local Multicast Name Resolution is not disabled." -ForegroundColor Yellow
    try {
        Write-Warning "Disable Link-Local Multicast Name Resolution?" -WarningAction Inquire
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMultiCast /t REG_DWORD /d 0 /f
        Write-Host "[LLMNR][SUCCESS] Link-Local Multicast Name Resolution was disabled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[LLMNR][WARN] Link-Local Multicast Name Resolution won't be disabled." -ForegroundColor Yellow
    }
}

# SMBv3 Signing
Write-Host "[SMB3][INFO] Checking SMBv3 Signing and Encryption..." -ForegroundColor Cyan
$smb3 = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EncryptData, EnableSecuritySignature
if ($smb3.RequireSecuritySignature -eq $true) {
    Write-Host "[SMB3][SUCCESS] Require Security Signature is true." -ForegroundColor Green
}
else {
    Write-Host "[SMB3][WARN] Require Security Signature is not true." -ForegroundColor Yellow
    try {
        Write-Warning "Change to true?" -WarningAction Inquire
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false
        Write-Host "[SMB3][SUCCESS] Changed to true" -ForegroundColor Green
    }
    catch {
        Write-Host "[SMB3][WARN] Will not change to true." -ForegroundColor Yellow
    }
}
if ($smb3.EncryptData -eq $true) {
    Write-Host "[SMB3][SUCCESS] EncryptData is true." -ForegroundColor Green
}
else {
    Write-Host "[SMB3][WARN] EncryptData is not true." -ForegroundColor Yellow
    try {
        Write-Warning "Change to true?" -WarningAction Inquire
        Set-SmbServerConfiguration -EncryptData $true -Confirm:$false
        Write-Host "[SMB3][SUCCESS] Changed to true" -ForegroundColor Green
    }
    catch {
        Write-Host "[SMB3][WARN] Will not change to true." -ForegroundColor Yellow
    }
}
if ($smb3.EnableSecuritySignature -eq $true) {
    Write-Host "[SMB3][SUCCESS] EnableSecuritySignature is true." -ForegroundColor Green
}
else {
    Write-Host "[SMB3][WARN] EnableSecuritySignature is not true." -ForegroundColor Yellow
    try {
        Write-Warning "Change to true?" -WarningAction Inquire
        Set-SmbServerConfiguration -EnableSecuritySignature $true -Confirm:$false
        Write-Host "[SMB3][SUCCESS] Changed to true" -ForegroundColor Green
    }
    catch {
        Write-Host "[SMB3][WARN] Will not change to true." -ForegroundColor Yellow
    }
}

Write-Host " "   
Write-Host "It's a good idea to run this again, and make sure all comes back okay."   

Stop-Transcript
exit 0