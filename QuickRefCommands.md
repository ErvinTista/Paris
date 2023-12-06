## Scanning and Enumeration

### NMAP
`nmap -sS IP`<br>
`nmap -sT IP`<br>
`nmap -sn IP_range`<br>
`nmap -sV -sC -p- -T4 $ip`<br>

### FeroxBuster for URLs
`feroxbuster --url domain --depth 2 --wordlist /usr/share/wordlists/common.txt`

### DNS Enumeration
`host domain`<br>
`host -t mx domain`<br>
`host -t txt domain`<br>
`dnsrecon -d domain -t std`<br>
`dnsenum domain`<br>
`nslookup -type=TXT domain IP`<br>

### TCP/UDP Port Scan
`nc -nvv -w -z IP port-port`

### Windows

### Linux

## Exploit

### Windows

### Linux

## Pivoting and Tunneling

### Windows

### Linux

## Persistence

### Windows

### Linux

## Shells and One Liners

### Windows

### Linux

