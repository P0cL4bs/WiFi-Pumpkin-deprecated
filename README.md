# 3vilTwinAttacker v0.6.3
Framework for EvilTwin Attacks
![Tool Home](https://dl.dropboxusercontent.com/u/97321327/evil/evil6.3.png)
![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
![Linux OS](https://img.shields.io/badge/Supported%20OS-Linux-green.svg)
![Release](https://img.shields.io/badge/3vilTwinAttacker-0.6.3%20-orange.svg)
![MIT License](https://img.shields.io/packagist/l/doctrine/orm.svg)
### dependencies:
* Python-scapy
* Python-nmap (optional)
* BeautifulSoup
* aircrack-ng
* DHCP-server

#### How to install on Ubuntu or Kali
```sh
$ git clone https://github.com/P0cL4bs/3vilTwinAttacker.git
$ cd 3vilTwinAttacker
$ sudo chmod +x installer.sh
$ sudo ./installer.sh --install
```
#### install DHCP in  Debian-based

##### Ubuntu

```sh
$ sudo apt-get install isc-dhcp-server
```

##### Kali linux

```sh
$ echo "deb http://ftp.de.debian.org/debian wheezy main " >> /etc/apt/sources.list
$ apt-get update && apt-get install isc-dhcp-server
```

#### install DHCP in  redhat-based

##### Fedora

```sh
$ sudo yum install dhcp
```
##### Blackarch or Arch Assault and Arch Linux
```sh
$ sudo pacman -S dhcp
```
### Tools

- Ettercap: Start ettercap attack in host connected AP fake Capturing login credentials.

-  Driftnet: The driftnet sniffs and decodes any JPEG TCP sessions, then displays in  an window.

### Modules
* Deauth Attack: kill all devices connected in AP (wireless network) or the attacker can Also put the Mac-address in the Client field, Then only one client disconnects the access point.

* Probe Request:  Probe request  capture the  clients trying to connect to AP,Probe requests can be sent by anyone with a legitimate Media Access Control (MAC) address, as association to the network is not required at this stage.

* Mac Changer: you can now easily spoof the MAC address. With a few clicks, users will be able to change their MAC addresses.

* DHCP Starvation Attack: this module DHCP Starvation can be classified as a Denial of Service attack. is an attack that works by broadcasting vast numbers of DHCP requests with spoofed MAC addresses simultaneously.

* Windows Update Attack: this module is an attack DNS spoof que generate an update the page fake Windows, causing the victim to download a fake file update.

* ARP Posion Attack:  change tables ARPspoof the target and redirect all request tcp to ip attacker.

* DNS Spoof Attack: this module DNS spoofing is the making change in hostname ip-address table, this table tells the route will be that DNS address for that particular IP address, thus changing the address of this table we can redirect wherever we want.


