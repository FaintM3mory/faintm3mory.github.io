---
title: Silver Platter
date: 2025-01-13
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, python, file_upload, path_traversal, webui_aria2, tomcat, ansible_playbook, ssh, burp, webshell, pspy64, tty_pushback]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/silverplatter/banner.png
---

> Think you've got what it takes to outsmart the Hack Smarter Security team? They claim to be unbeatable, and now it's [your chance](https://tryhackme.com/r/room/silverplatter) to prove them wrong. Dive into their web server, find the hidden flags, and show the world your elite hacking skills. Good luck, and may the best hacker win!
>
> But beware, this won't be a walk in the digital park. Hack Smarter Security has fortified the server against common attacks and their password policy requires passwords that have not been breached (they check it against the rockyou.txt wordlist - that's how 'cool' they are). The hacking gauntlet has been thrown, and it's time to elevate your game. Remember, only the most ingenious will rise to the top.
>
>May your code be swift, your exploits flawless, and victory yours!

## Recon & Initial Access

Let's start! Here is the nmap scan :

```shell
nmap -sS -sV -T4 $TARGET
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-11 15:39 CET
Nmap scan report for 10.10.34.36
Host is up (0.035s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
8080/tcp open  http-proxy

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.96 seconds
```

There is a **web server** on port `80` under nginx and another **http-proxy** on port `8080`. As I explore the website, I see a few important words (like a username) that we could use later such as `scr1ptkiddy` or `Silverpeas`.

![1](/assets/img/tryhackme/ctf/silverplatter/1.png)

![2](/assets/img/tryhackme/ctf/silverplatter/2.png)

I decided to enumerate both applications using **Gobuster** : 

```shell
# The first application on port 80
$ gobuster dir -u http://10.10.34.36:80 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 30 -x php,html,jpg
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.34.36:80
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 178] [--> http://10.10.34.36/assets/]
/images               (Status: 301) [Size: 178] [--> http://10.10.34.36/images/]
/index.html           (Status: 200) [Size: 14124]
/index.html           (Status: 200) [Size: 14124]
Progress: 18936 / 18940 (99.98%)
===============================================================
Finished
===============================================================
```

```shell
# The second application on port 8080
$ gobuster dir -u http://10.10.34.36:8080 -w /usr/share/wordlists/seclists/Discovery/Web-Content/commo
n.txt -t 30 -x php,html,jpg
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.34.36:8080
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/console              (Status: 302) [Size: 0] [--> /noredirect.html]
/website              (Status: 302) [Size: 0] [--> http://10.10.34.36:8080/website/]
Progress: 18936 / 18940 (99.98%)
===============================================================
Finished
===============================================================
```

I could not find anything interesting on these directories, so I tried a different approach. After all, maybe the right directory isn't in a wordlist ?

That is how I found the **silverpeas** website on port `8080` :

![3](/assets/img/tryhackme/ctf/silverplatter/3.png)

We already know the username `scr1ptkiddy` from the original website, but what could be the password ?

Using **sqlmap** to test for SQL injections did not work.

Maybe there is a way to bypass the authentication system ? Well apparently yes ! According to the **CVE-2024-36042** vulnerability, we can [bypass the authentication system](https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d) by erasing the `Password` parameter when sending the POST request.

So, this is what our request looks like using the `scr1ptkiddy` user for logging in :

![4](/assets/img/tryhackme/ctf/silverplatter/4.png)

And we bypass the authentication in order to obtain the access to the portal :

![5](/assets/img/tryhackme/ctf/silverplatter/5.png)

![6](/assets/img/tryhackme/ctf/silverplatter/6.png)

We have the contact pages with the different users. In the meantime, I switched to the **SilverAdmin** user on Silverpeas which is the default admin user.

Searching through the vulnerabilities on Silverpeas, I found this [Broken Access Control](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2023-47323) that allows to read any messages (even admin-only).

Using it, we can go through the different messages that were sent that could contain important information to use.

On one of these messages (`ID=6`), the Administrator left a message containing some **SSH credentials** for a user called `tim` :

![7](/assets/img/tryhackme/ctf/silverplatter/7.png)

We immediately use those credentials to get a foothold on the machine and obtain the **first flag** :

```shell
$ ssh tim@$TARGET
The authenticity of host '10.10.223.121 (10.10.223.121)' can't be established.
ED25519 key fingerprint is SHA256:WFcHcO+oxUb2E/NaonaHAgqSK3bp9FP8hsg5z2pkhuE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.223.121' (ED25519) to the list of known hosts.
tim@10.10.223.121's password:

[...]

Last login: Wed Dec 13 16:33:12 2023 from 192.168.1.20

tim@silver-platter:~$ ls
user.txt
tim@silver-platter:~$ cat user.txt
THM{[REDACTED]}
```

## Privilege Escalation

Is there any way we can escalate our privileges with the `tim` user ? First of all, we type the few obvious commands to retrieve some information after our foothold :

```shell
tim@silver-platter:~$ sudo -l
[sudo] password for tim:
Sorry, user tim may not run sudo on silver-platter.
tim@silver-platter:~$ ls -la
total 12
dr-xr-xr-x 2 root root 4096 Dec 13  2023 .
drwxr-xr-x 4 root root 4096 Dec 13  2023 ..
-rw-r--r-- 1 root root   38 Dec 13  2023 user.txt
tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
```

### Rabbit Hole

Before considering the obvious hint that I had under my eyes from the beginning (the groups the `tim` user is in), I also saw that there is another [vulnerability](https://rhinosecuritylabs.com/research/silverpeas-file-read-cves/) that allows to read files on the server as **root**. 

As the `SilverAdmin` on the Silverpeas web app, I headed to the **Administration** tab and create a new **space**. Inside this space, it's possible *"Add an application"* called **Silvercrawler** (which is a connector that allows us to have a read access to the machine's filesystem as **root**).

![8](/assets/img/tryhackme/ctf/silverplatter/8.png)

This vulnerability is great in itself... But not very useful here as the application is inside a container...

### Another try

This time, it's the good one because I decided to concentrate on the information I got from the `id` command :

```shell
tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
```

The output tells us that our user is part of the `adm` group which is, in Linux, a system group that typically grants users access to certain **administrative tasks**, primarily related to reading **log files** (such as in `/var/log`). We will try something with it :

```shell
tim@silver-platter:/var/log$ ls -l
total 2096
-rw-r--r--  1 root      root                 0 May  1  2024 alternatives.log
-rw-r--r--  1 root      root             34877 Dec 12  2023 alternatives.log.1
drwx------  3 root      root              4096 May  8  2024 amazon
drwxr-xr-x  2 root      root              4096 May  1  2024 apt
-rw-r-----  1 syslog    adm                913 Jan 13 17:57 auth.log
-rw-r-----  1 syslog    adm               6356 Jan 13 17:54 auth.log.1
-rw-r-----  1 syslog    adm              32399 Dec 13  2023 auth.log.2
-rw-r-----  1 syslog    adm                755 May  8  2024 auth.log.2.gz
-rw-r--r--  1 root      root               600 May  8  2024 aws114_ssm_agent_installation.log
-rw-r--r--  1 root      root             64549 Aug 10  2023 bootstrap.log
-rw-rw----  1 root      utmp                 0 Jan 13 17:54 btmp
-rw-rw----  1 root      utmp               384 May  1  2024 btmp.1
-rw-r-----  1 syslog    adm             680197 Jan 13 17:55 cloud-init.log
-rw-r-----  1 root      adm              32825 Jan 13 17:55 cloud-init-output.log
drwxr-xr-x  2 root      root              4096 Aug  2  2023 dist-upgrade
-rw-r-----  1 root      adm              47889 Jan 13 17:54 dmesg
-rw-r-----  1 root      adm              45164 May  8  2024 dmesg.0
-rw-r-----  1 root      adm              14486 May  8  2024 dmesg.1.gz
-rw-r-----  1 root      adm              14519 May  8  2024 dmesg.2.gz
-rw-r-----  1 root      adm              14523 May  1  2024 dmesg.3.gz
-rw-r-----  1 root      adm              14543 Dec 13  2023 dmesg.4.gz
-rw-r--r--  1 root      root                 0 Jan 13 17:54 dpkg.log
-rw-r--r--  1 root      root               490 May  8  2024 dpkg.log.1
-rw-r--r--  1 root      root             50823 Dec 13  2023 dpkg.log.2.gz
-rw-r--r--  1 root      root             32064 Dec 13  2023 faillog
drwxr-x---  4 root      adm               4096 Dec 12  2023 installer
drwxr-sr-x+ 3 root      systemd-journal   4096 Dec 12  2023 journal
-rw-r-----  1 syslog    adm               2523 Jan 13 17:55 kern.log
-rw-r-----  1 syslog    adm             186095 Jan 13 17:54 kern.log.1
-rw-r-----  1 syslog    adm              27571 May  8  2024 kern.log.2.gz
-rw-r-----  1 syslog    adm              82570 Dec 13  2023 kern.log.3.gz
drwxr-xr-x  2 landscape landscape         4096 Dec 12  2023 landscape
-rw-rw-r--  1 root      utmp            292584 Jan 13 17:57 lastlog
drwxr-xr-x  2 root      adm               4096 Jan 13 17:54 nginx
drwx------  2 root      root              4096 Aug 10  2023 private
-rw-r-----  1 syslog    adm              40834 Jan 13 17:58 syslog
-rw-r-----  1 syslog    adm             394534 Jan 13 17:54 syslog.1
-rw-r-----  1 syslog    adm              47656 May  8  2024 syslog.2.gz
-rw-r-----  1 syslog    adm             147601 May  1  2024 syslog.3.gz
-rw-r--r--  1 root      root                 0 Aug 10  2023 ubuntu-advantage.log
drwxr-x---  2 root      adm               4096 Jan 13 17:54 unattended-upgrades
-rw-rw-r--  1 root      utmp             25728 Jan 13 17:57 wtmp
```

We have a bunch of files that we can look into for possible credentials that were left in clear text, but we mostly want to check for the **authentication logs** such as `auth.log`, `auth.log.1` and `auth.log.2`.

Indeed, in the third file we can see that the user `tyler` ran a container service with a postgresql database and wrote the credentials in this **same command** (luckily for us) :

```shell
tim@silver-platter:/var/log$ cat auth.log.2 | grep -i "password"
Dec 12 19:34:46 silver-platter passwd[1576]: pam_unix(passwd:chauthtok): password changed for tim
Dec 12 19:39:15 silver-platter sudo:    tyler : 3 incorrect password attempts ; TTY=tty1 ; PWD=/home/tyler ; USER=root ; COMMAND=/usr/bin/apt install nginx
Dec 13 15:39:07 silver-platter usermod[1597]: change user 'dnsmasq' password
Dec 13 15:39:07 silver-platter chage[1604]: changed password expiry for dnsmasq
Dec 13 15:40:33 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql -d -e POSTGRES_PASSWORD=_Zd_zx7N823/ -v postgresql-data:/var/lib/postgresql/data postgres:12.3
Dec 13 15:44:30 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=[REDACTED] -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database sivlerpeas:silverpeas-6.3.1
Dec 13 15:45:21 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=[REDACTED] -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:silverpeas-6.3.1
Dec 13 15:45:57 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=[REDACTED] -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:6.3.1
Dec 13 16:17:31 silver-platter passwd[6811]: pam_unix(passwd:chauthtok): password changed for tim
Dec 13 16:18:57 silver-platter sshd[6879]: Accepted password for tyler from 192.168.1.20 port 47772 ssh2
Dec 13 16:32:54 silver-platter passwd[7174]: pam_unix(passwd:chauthtok): password changed for tim
Dec 13 16:33:12 silver-platter sshd[7181]: Accepted password for tim from 192.168.1.20 port 50970 ssh2
Dec 13 16:35:45 silver-platter sshd[7297]: Accepted password for tyler from 192.168.1.20 port 58172 ssh2
Dec 13 16:45:33 silver-platter sshd[7622]: Accepted password for tyler from 192.168.1.20 port 33484 ssh2
Dec 13 17:43:09 silver-platter sshd[7750]: Accepted password for tyler from 192.168.1.20 port 45796 ssh2
Dec 13 17:51:30 silver-platter sshd[1370]: Accepted password for tyler from 192.168.1.20 port 60860 ssh2
Dec 13 17:51:41 silver-platter sshd[1681]: Accepted password for tyler from 192.168.1.20 port 55392 ssh2
```

We have a new information that we could maybe get advantage from by using it somewhere else. In fact, by just checking and without even expecting it, this password is also the one used for the `tyler` account on the machine.

On top of that, by checking the `sudo -l` command output, we notice that `tyler` has full access over any command using `sudo`, so we can read the **root flag** in `/root`.

```shell
tim@silver-platter:/var/log$ su tyler
Password:
tyler@silver-platter:/var/log$ id
uid=1000(tyler) gid=1000(tyler) groups=1000(tyler),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
tyler@silver-platter:~$ sudo -l
[sudo] password for tyler:
Matching Defaults entries for tyler on silver-platter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
tyler@silver-platter:~$ sudo cat /root/root.txt
THM{[REDACTED]}
```