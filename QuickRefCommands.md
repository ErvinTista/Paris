## Scanning and Enumeration

#### NMAP
`nmap -sS IP`<br>
`nmap -sT IP`<br>
`nmap -sn IP_range`<br>
`nmap -sV -sC -p- -T4 $ip`<br>

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
`feroxbuster --url domain --depth 2 --wordlist /usr/share/wordlists/common.txt -x .txt,.jpg`<br>

## Exploit

#### Password Cracking
hashcat -a 0 -m #hash_type hash.txt dictionary_list.txt

## Pivoting and Tunneling

## Persistence

## Shells and One Liners

