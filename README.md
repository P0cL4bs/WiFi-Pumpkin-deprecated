# 3vilTwinAttacker v0.6.4
Framework for EvilTwin Attacks
![Tool Home](https://dl.dropboxusercontent.com/u/97321327/evil/evil6.4.png)
![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
![Linux OS](https://img.shields.io/badge/Supported%20OS-Linux-green.svg)
![Release](https://img.shields.io/badge/3vilTwinAttacker-0.6.4%20-orange.svg)
![MIT License](https://img.shields.io/packagist/l/doctrine/orm.svg)

###Description
3vilTwinAttacker is security tool that  provide the Rogue access point to Man-In-The-Middle and network attacks. purporting to provide wireless Internet services, but snooping on the traffic. can be used to capture of credentials of unsuspecting users by either snooping the communication by phishing.

### dependencies:
* Python-scapy
* Python-nmap (optional)
* BeautifulSoup
* isc-dhcp-server

#### How to install on Ubuntu or Kali 2.0
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
----script .sh----
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


