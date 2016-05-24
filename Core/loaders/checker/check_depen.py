#coding: utf-8
from os import path,popen,remove,system,chdir
from shutil import copy
import sys
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[91m'
ENDC = '\033[0m'

def notinstall(app):
    print '[%s✘%s] %s is not %sinstalled%s.'%(RED,ENDC,app,YELLOW,ENDC)

def check_dep_pumpkin():
    if sys.version_info.major != 2:
        print("WiFi-Pumpkin need Python 2 :(")
        sys.exit(-1)
    hostapd = popen('which hostapd').read().split("\n")
    dhcpd = popen('which dhcpd').read().split("\n")
    lista = [dhcpd[0],hostapd[0]]
    m = []
    for i in lista:
        m.append(path.isfile(i))
    for k,g in enumerate(m):
        if m[k] == False:
            if k == 0:notinstall('isc-dhcp-server')
            if k == 1:notinstall('hostapd')
    if not path.isfile('Templates/Update/Windows_Update/Settins_WinUpdate.html'):
        if '/usr/bin/wifi-pumpkin' in sys.argv[0]:
            chdir('/usr/share/WiFi-Pumpkin')
        copy('Settings/source.tar.gz','Templates/')
        system('cd Templates/ && tar -xf source.tar.gz')
        remove('Templates/source.tar.gz')
