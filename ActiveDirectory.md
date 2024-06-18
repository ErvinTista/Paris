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

List of usernames - https://github.com/insidetrust/statistically-likely-usernames


### Initial Access

### Internal enumeration - Services, Accounts, 
