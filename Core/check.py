#coding: utf-8
from os import path,popen
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
                print '[%s✘%s] DHCP not %sfound%s.'%(RED,ENDC,YELLOW,ENDC)
    for c in m:
        if c == False:
            exit(1)
        break