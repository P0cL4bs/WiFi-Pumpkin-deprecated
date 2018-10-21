#coding: utf-8
from core.utility.collection import SettingsINI
from os import path,popen,remove,system
from shutil import copy
import core.utility.constants as C

def notinstall(app):
    print '[%s✘%s] %s is not %sinstalled%s.'%(C.RED,C.ENDC,app,C.YELLOW,C.ENDC)

def check_dep_pumpkin():
    # check hostapd
    hostapd = popen('which hostapd').read().split('\n')
    if not path.isfile(hostapd[0]): notinstall('hostapd')
    # checck source.tar.gz tamplate module
    if not path.isfile(C.TEMPLATES):
        system(C.EXTRACT_TEMP)
    if not path.isabs(C.TEMPLATES_WWW):
        system(C.EXTRACT_WWW)

    # check if hostapd is found and save path
    settings = SettingsINI(C.CONFIG_INI)
    hostapd_path = settings.get_setting('accesspoint','hostapd_path')
    if not path.isfile(hostapd_path) and len(hostapd[0]) > 2:
        return settings.set_setting('accesspoint','hostapd_path',hostapd[0])
    elif not path.isfile(hostapd[0]):
        return settings.set_setting('accesspoint','hostapd_path','0')