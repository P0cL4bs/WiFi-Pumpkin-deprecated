#coding: utf-8
from core.utility.collection import SettingsINI
from os import path,popen,remove,system
from shutil import copy
YELLOW = '\033[33m'
RED = '\033[91m'
ENDC = '\033[0m'

def notinstall(app):
    print '[%s✘%s] %s is not %sinstalled%s.'%(RED,ENDC,app,YELLOW,ENDC)

def check_dep_pumpkin():
    hostapd = popen('which hostapd').read().split('\n')
    dhcpd = popen('which dhcpd').read().split('\n')
    deps = []
    lista = [dhcpd[0],hostapd[0]]
    for i in lista: deps.append(path.isfile(i))
    for k,g in enumerate(deps):
        if deps[k] == False:
            if k == 0:notinstall('isc-dhcp-server')
            if k == 1:notinstall('hostapd')
    if not path.isfile('templates/Update/Windows_Update/Settins_WinUpdate.html'):
        copy('settings/source.tar.gz','templates/')
        system('cd templates/ && tar -xf source.tar.gz')
        remove('templates/source.tar.gz')

    # check if hostapd is found and save path
    settings = SettingsINI('core/config/app/config.ini')
    hostapd_path = settings.get_setting('accesspoint','hostapd_path')
    if not path.isfile(hostapd_path) and len(hostapd[0]) > 2:
        return settings.set_setting('accesspoint','hostapd_path',hostapd[0])
    elif not path.isfile(hostapd[0]):
        return settings.set_setting('accesspoint','hostapd_path','0')