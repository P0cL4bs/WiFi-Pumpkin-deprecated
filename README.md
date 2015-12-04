
3vilTwinAttacker
---
Framework for Rogue Wi-Fi Access Point Attack

![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
![Linux OS](https://img.shields.io/badge/Version-0.6.8-red.svg)
![Linux OS](https://img.shields.io/badge/Supported%20OS-Linux-green.svg)
[![build](https://travis-ci.org/P0cL4bs/3vilTwinAttacker.svg)](https://travis-ci.org/P0cL4bs/3vilTwinAttacker/)
### Description
3vilTwinAttacker is security tool that  provide the Rogue access point to Man-In-The-Middle and network attacks. purporting to provide wireless Internet services, but snooping on the traffic. can be used to capture of credentials of unsuspecting users by either snooping the communication by phishing.

### Dependencies
* python-qt4
* python-scapy
* python-nmap (optional)
* python-BeautifulSoup
* hostapd
* isc-dhcp-server

### Tested On
* Kali linux 2.0
* WifiSlax 4.11.1 VMware Edition
* Ubuntu 14.04 LTS

### Installation

#### install on Ubuntu or Kali 2.0
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

##### Kali 2.0
----script.sh----
```sh
check_arch=$(uname -m)
if [ "$check_arch" = "i686" ]; then
    wget http://http.kali.org/kali/pool/main/i/isc-dhcp/isc-dhcp-server_4.3.1-6_i386.deb
    dpkg -i isc-dhcp-server_4.3.1-6_i386.deb
elif [ "$check_arch" = "x86_64" ]; then
    wget http://http.kali.org/kali/pool/main/i/isc-dhcp/isc-dhcp-server_4.3.1-6_amd64.deb
    dpkg -i isc-dhcp-server_4.3.1-6_amd64.deb
fi
```

##### Fedora

```sh
$ sudo yum install dhcp
```
##### Blackarch or Arch Assault and Arch Linux
```sh
$ sudo pacman -S dhcp
```

### Features
* Rouge Wi-Fi Access Point
* Deauth Clients AP 
* Probe Request Monitor
* DHCP Starvation Attack
* Crendentials Monitor
* Windows Update Attack
* Templates phishing
* Partial bypass HSTS
* Dump credentials phishing
* Support airodump scan
* Support mkd3 deauth
* beef hook support
* Report Logs html
* Mac Changer 
* ARP Posion 
* DNS Spoof 
* Plugins
    - net-creds
    - sslstrip
    - dns2proxy
* Tools
    - ettercap
	- driftnet

### Screenshot
![Tool Home](https://dl.dropboxusercontent.com/u/97321327/evil/evil6.8.png)

### Issues
Find a bug? Want more features?  Let us know! Please send [file an issue](https://github.com/P0cL4bs/3vilTwinAttacker/issues/new) 
