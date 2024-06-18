### Scanning, Enumeration, Recon, External

Scan for live hosts on network
```
fping -asgq sub.net.ip/24
```

Kerbrute for internal AD username enumeration
```
sudo git clone https://github.com/ropnop/kerbrute.git
sudo make all
kerbrute userenum -d <domain.local> --dc <domain.ip.number> <usernametextfile-to-test> -o valid_ad_users.txt
```

Kerbrute can be used to password spray
```
/kerbrute_linux_amd64 passwordspray -d <lab.ropnop.com> <domain_users.txt> <Password123>
```

Link for Kerbrute - https://github.com/ropnop/kerbrute

List of usernames - https://github.com/insidetrust/statistically-likely-usernames

Enumerate Password Policy with CME
```
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

rpcclient to check a Domain Controller for SMB NULL session access
```
rpcclient -U "" -N <domain.ip>
then querydomaininfo to check password policy
```

enum3linux can enumerate windows hosts and domains
```
enum4linux -P <domain.ip>
```

enum4linux-ng is a rewrite and has additional features. -oA will output a JSON  and YAML file
```
enum4linux-ng -P <domain.ip> -oA save
```

Establish a null session on windows
```
net use \\DC01\ipc$ "" /u:""
```

LDAP anonymous binds allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. From Linux.
```
ldapsearch -h <dc.ip> -x -b "DC=<domain-name>,DC=<LOCAL>" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

### Initial Access

### Internal enumeration - Services, Accounts, 
