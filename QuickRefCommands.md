## Scanning and Enumeration

### NMAP
`nmap -sS IP`
`nmap -sT IP`
`nmap -sn IP_range`
`nmap -sV -sC -p- -T4 $ip`

### FeroxBuster for URLs
`feroxbuster --url domain --depth 2 --wordlist /usr/share/wordlists/common.txt`

### DNS Enumeration
`host domain`
`host -t mx domain`
`host -t txt domain`
`dnsrecon -d domain -t std`
`dnsenum domain`
`nslookup -type=TXT domain IP`

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

