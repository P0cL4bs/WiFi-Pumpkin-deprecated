#coding: utf-8
from os import path,popen,remove,system
from shutil import copy
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[91m'
ENDC = '\033[0m'
def check_dependencies():
    ettercap = popen('which ettercap').read().split("\n")
    dhcpd = popen('which dhcpd').read().split("\n")
    lista = [dhcpd[0],'/usr/sbin/airbase-ng',
    ettercap[0]]
    m = []
    for i in lista:
        m.append(path.isfile(i))
    for k,g in enumerate(m):
        if m[k] == False:
            if k == 0:
                print '[%s✘%s] isc-dhcp-server not %sinstalled%s.'%(RED,ENDC,YELLOW,ENDC)
    if not path.isfile('Templates/Update/Windows_Update/Settins_WinUpdate.html'):
        copy('Settings/source.tar.gz','Templates/')
        system('cd Templates/ && tar -xf source.tar.gz')
        remove('Templates/source.tar.gz')