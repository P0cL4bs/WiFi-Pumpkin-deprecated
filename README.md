# 3vilTwinAttacker v0.6.3
Framework for EvilTwin Attacks
![Tool Home](https://dl.dropboxusercontent.com/u/97321327/evil/evil6.3.png)
---
### dependencies:
* Python-scapy
* Python-nmap (optional)
* BeautifulSoup
* aircrack-ng
* DHCP-server


#### Ubuntu and Kali install
```sh
$ chmod +x installer.sh
```
```sh
$ sudo ./installer --install
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

## Videos tutorials:
[Demo 1](http://www.youtube.com/watch?v=Jrb43KVPIJw)
--
[Demo 2](http://youtu.be/qVGLGNYyLzg)
--
[Demo 3](http://youtu.be/rNWvpV6NZoI)
--
The MIT License (MIT)

Copyright (c) 2015 P0cL4bs Team

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
