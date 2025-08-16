Write-Host "[*] Reverting security hardening changes..." -ForegroundColor Cyan

# --- Security Policy Changes ---
# Everyone can log on locally
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg).replace("SeDenyInteractiveLogonRight = *S-1-5-21*", "") | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS
Remove-Item C:\secpol.cfg -Force
Write-Host "[+] Everyone can log on locally"

# Account
net accounts /lockoutduration:100
net accounts /lockoutthreshold:0
net accounts /lockoutwindow:0
net accounts /minpwlen:5     
net accounts /maxpwage:90    
net accounts /minpwage:0    
net accounts /uniquepw:0

# Enable Guest account
net user guest /active:yes
Write-Host "[+] Guest account enabled"

# Disable blank password restriction
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 0 /f
Write-Host "[+] Blank password restriction disabled"

# Disable UAC installer detection
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 0 /f
Write-Host "[+] UAC installer detection disabled"

# Disable SMB signing
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f
Write-Host "[+] SMB signing disabled"

# Allow SAM enumeration
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 0 /f
Write-Host "[+] SAM enumeration allowed"

# Disable Logon Auditing
auditpol /set /subcategory:"Logon" /success:disable /failure:disable
wevtutil el | ForEach-Object { wevtutil cl $_ }
Write-Host "[+] Logon auditing disabled"

# --- Enable RDP (without firewall rule changes) ---
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Write-Host "[+] Remote Desktop enabled"

# --- Create user1 (normal user only) ---
Write-Host "[*] Creating user1..."
net user user1 password /add
wmic useraccount where "name='user1'" set disabled=false
net localgroup "Users" user1 /add
Write-Host "[+] User 'user1' created with password 'password' (normal user only)"

# Take ownership of PowerShell executables
takeown /f "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
takeown /f "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
Write-Host "[+] Ownership of PowerShell files taken"

# Restore PowerShell access for 'user1'
icacls "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /remove:d user1
icacls "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" /remove:d user1
Write-Host "[+] PowerShell access restored for user1"

# Enable Telnet Client
dism /online /Enable-Feature /FeatureName:TelnetClient

# FIle Transfer
# Variables
$serverIP = "192.168.60.45"
$port = "1111"
$downloadPath = "$env:USERPROFILE\Downloads"
$desktopPath = [Environment]::GetFolderPath("Desktop")

# Files to download
$files = @("CIS-CAT.zip", "kpym.exe")

# Create download folder if not exists
if (!(Test-Path $downloadPath)) {
    New-Item -ItemType Directory -Path $downloadPath | Out-Null
}

# Download files
foreach ($file in $files) {
    $url = "http://$serverIP`:$port/$file"
    $destination = Join-Path $downloadPath $file
    Invoke-WebRequest -Uri $url -OutFile $destination
    Write-Output "Downloaded: $file"
}

# Unzip CIS-CAT.zip
$zipFile = Join-Path $downloadPath "CIS-CAT.zip"
$extractPath = Join-Path $downloadPath "CIS-CAT"
Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force

# Create shortcut for Assessor-GUI.exe inside CIS-CAT\Assessor\
$targetExe = Join-Path $extractPath "Assessor\Assessor-GUI.exe"
$shortcutPath = Join-Path $desktopPath "Assessor-GUI.lnk"

$WScriptShell = New-Object -ComObject WScript.Shell
$shortcut = $WScriptShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetExe
$shortcut.WorkingDirectory = (Split-Path $targetExe)
$shortcut.Save()

Write-Output "Shortcut created on Desktop for Assessor-GUI.exe"

Write-Host "[*] Script completed. Please restart the computer."
