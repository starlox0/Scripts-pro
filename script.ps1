# --- Reverse Hardening Script (with RDP enabled, no firewall rules) ---
# Run as Administrator

Write-Host "[*] Reverting security hardening changes..."

# 1. Allow 'Everyone' to log on locally
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace 'SeInteractiveLogonRight = .*', 'SeInteractiveLogonRight = *S-1-1-0' | Set-Content C:\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS
Remove-Item C:\secpol.cfg
Write-Host "[+] Everyone can log on locally"

# 2. Enable Guest account
net user guest /active:yes
Write-Host "[+] Guest account enabled"

# 3. Disable blank password restriction
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 0 /f
Write-Host "[+] Blank password restriction disabled"

# 4. Disable UAC prompt for installs
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 0 /f
Write-Host "[+] UAC installer detection disabled"

# 5. Disable Microsoft network signing requirement
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f
Write-Host "[+] SMB signing disabled"

# 6. Allow anonymous SAM enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 0 /f
Write-Host "[+] SAM enumeration allowed"

# 7. Disable auditing of logon attempts
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable
auditpol /clear
Write-Host "[+] Logon auditing disabled"

# 8. Enable Telnet Client
dism /online /Enable-Feature /FeatureName:TelnetClient
Write-Host "[+] Telnet client enabled"

# 9. Add new user 'user1' with password 'password'
net user user1 password /add
net localgroup Users user1 /add
Write-Host "[+] Added new user: user1 (password: password)"

# 10. Take ownership of PowerShell executables
takeown /f "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
takeown /f "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
Write-Host "[+] Ownership of PowerShell files taken"

# 11. Restore PowerShell access for 'user1'
icacls "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /remove:d user1
icacls "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" /remove:d user1
Write-Host "[+] PowerShell access restored for user1"

# 12. Enable Remote Desktop (no firewall rule changes)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Write-Host "[+] Remote Desktop enabled (firewall rules untouched)"

Write-Host "[*] Reverse hardening complete."
