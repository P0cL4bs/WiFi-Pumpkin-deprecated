import os
import sys
from pwd import getpwnam
from grp import getgrnam
from PyQt4 import Qt, QtGui, QtCore
from logging import getLogger,ERROR
from core.utility.settings import frm_Settings as SuperSettings
from core.utils import (
    Refactor,set_monitor_mode,waiterSleepThread,
    setup_logger,is_ascii,is_hexadecimal,exec_bash,del_item_folder
)
import core.utility.constants as C
from collections import OrderedDict
from functools import  partial
from core.utility.component import ComponentBlueprint
from netaddr import EUI


def deleteObject(obj):
    ''' reclaim memory '''
    del obj
def ProgramPath(executablename):
    expath = os.popen('which {}'.format(executablename)).read().split('\n')[0]

    if os.path.isfile(expath):
        return expath
    else:
        return False

def get_mac_vendor(mac):
    ''' discovery mac vendor by mac address '''
    try:
        d_vendor = EUI(mac)
        d_vendor = d_vendor.oui.registration().org
    except:
        d_vendor = 'unknown mac'
    return d_vendor



__all__ = ["deleteObject","os","sys","Qt","QtGui","QtCore","SuperSettings","getLogger","ERROR",
           "C","OrderedDict","partial","Refactor","set_monitor_mode","waiterSleepThread","setup_logger",
           "is_ascii","is_hexadecimal","exec_bash","del_item_folder","ComponentBlueprint","getgrnam",
           "getpwnam","ProgramPath","get_mac_vendor"]

#root = QtCore.QCoreApplication.instance()
#Settings = root.Settings
#__all__.append["Settings"]