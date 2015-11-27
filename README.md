
3vilTwinAttacker
---
Framework for Rogue Wi-Fi Access Point Attack

![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
![Linux OS](https://img.shields.io/badge/Version-0.6.7-red.svg)
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
* Ubuntu 14.04.3 LTS

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
* Tools
    - ettercap
	- driftnet

### Screenshot
![Tool Home](https://dl.dropboxusercontent.com/u/97321327/evil/evil6.7.png)

### Issues
Find a bug? Want more features?  Let us know! Please send [file an issue](https://github.com/P0cL4bs/3vilTwinAttacker/issues/new) 

### License
The MIT License (MIT)

Copyright (c) 2015-2016 P0cL4bs Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.