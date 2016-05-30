from sys import exit,stdout
from struct import pack
from time import sleep,asctime,strftime
from random import randint
from os import popen,path,walk,system,getpid,stat
from subprocess import call,check_output,Popen,PIPE,STDOUT
from re import search,compile,VERBOSE,IGNORECASE
import threading
import netifaces
from threading import Thread
import Queue
from scapy.all import *
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import logging
import configparser

"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    for modules.

Copyright:
    Copyright (C) 2015 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

class set_monitor_mode(QDialog):
    def __init__(self,interface,parent = None):
        super(set_monitor_mode, self).__init__(parent)
        self.interface = interface
    def setEnable(self):
        try:
            output  = check_output(['ifconfig', self.interface, 'down'])
            output += check_output(['iwconfig', self.interface, 'mode','monitor'])
            output += check_output(['ifconfig', self.interface, 'up'])
            if len(output) > 0:QMessageBox.information(self,'Monitor Mode',
            'device %s.%s'%(self.interface,output))
            return self.interface
        except Exception ,e:
            QMessageBox.information(self,'Monitor Mode',
            'mode on device %s.your card not supports monitor mode'%(self.interface))
    def setDisable(self):
        Popen(['ifconfig', self.interface, 'down'])
        Popen(['iwconfig', self.interface, 'mode','managed'])
        Popen(['ifconfig', self.interface, 'up'])


class ThreadPhishingServer(QThread):
    send = pyqtSignal(str)
    def __init__(self,cmd,):
        QThread.__init__(self)
        self.cmd     = cmd
        self.process = None

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT)
        for line in iter(self.process.stdout.readline, b''):
            self.send.emit(line.rstrip())

    def stop(self):
        print 'Stop thread:' + self.objectName()
        if self.process is not None:
            self.process.terminate()



'''http://stackoverflow.com/questions/17035077/python-logging-to-multiple-log-files-from-different-classes'''
def setup_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.StreamHandler(stdout)
    formatter = logging.Formatter('%(asctime)s : %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    l.setLevel(logging.INFO)
    l.addHandler(fileHandler)

class Refactor:
    @staticmethod
    def htmlContent(title):
        html = {'htmlheader':[
            '<html>',
            '<head>',
            '<title>'+title+'</title>',
            '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">',
            '<style type="text/css">',
            '.ln { color: rgb(0,0,0); font-weight: normal; font-style: normal; }',
            '.s0 { color: rgb(128,128,128); }',
            '.s1 { color: rgb(169,183,198); }',
            '.s2 { color: rgb(204,120,50); font-weight: bold; }',
            '.s3 { color: rgb(204,120,50); }',
            '.s4 { color: rgb(165,194,97); }',
            '.s5 { color: rgb(104,151,187); }',
            '</style>',
            '</head>',
            '<BODY BGCOLOR="#2b2b2b">',
            '<TABLE CELLSPACING=0 CELLPADDING=5 COLS=1 WIDTH="100%" BGCOLOR="#C0C0C0" >',
            '<TR><TD><CENTER>',
            '<FONT FACE="Arial, Helvetica" COLOR="#000000">'+title+'</FONT>',
            '</center></TD></TR></TABLE>',
            '<pre>',
            ]
        }
        return html
    @staticmethod
    def exportHtml():
        readFile = {
         'dhcp': {'Logs/AccessPoint/dhcp.log':[]},
         'urls': {'Logs/AccessPoint/urls.log':[]},
         'credentials': {'Logs/AccessPoint/credentials.log':[]},
         'requestAP': {'Logs/AccessPoint/requestAP.log':[]},
         #'dns2proxy': {'Logs/AccessPoint/dns2proxy.log':[]},
         #'injectionPage': {'Logs/AccessPoint/injectionPage.log':[]},
         'phishing': {'Logs/Phishing/Webclone.log':[]},}
        for i in readFile.keys():
            for j in readFile[i]:
                with open(j,'r') as file:
                    readFile[i][j] = file.read()

        contenthtml,HTML = Refactor.htmlContent('Report Logger'),''
        for i in contenthtml['htmlheader']: HTML += i+"\n"
        HTML += '</span><span class="s5">Report Generated at::</span><span class="s0">'+asctime()+'</span>\n'
        HTML += '</span><span class="s4"><br></span><span class="s1">\n'
        for key in readFile.keys():
            if Refactor.getSize(readFile[key].keys()[0]) > 0:
                HTML += '</span><span class="s2">-[ {} Logger ]-</span><span class="s1">\n'.format(key)
                HTML += readFile[key][readFile[key].keys()[0]]
                HTML += '</span><span class="s4"><br><br></span><span class="s1">\n'
        HTML += '</span></pre>\n<TABLE CELLSPACING=0 CELLPADDING=5 COLS=1 WIDTH="100%" BGCOLOR="#C0C0C0" >\
        <TR><TD><CENTER>''<FONT FACE="Arial, Helvetica" COLOR="#000000">WiFi-Pumpkin (C) 2015 P0cL4bs Team' \
        '</FONT></center></TD></TR></TABLE></body>\n</html>\n'

        Load_ = {'HTML': HTML,'Files':[readFile[x].keys()[0] for x in readFile.keys()]}
        return Load_

    @staticmethod
    def settingsNetworkManager(interface=str,Remove=False):
        ''' mac address of interface to exclude '''
        networkmanager = '/etc/NetworkManager/NetworkManager.conf'
        config = configparser.RawConfigParser()
        config.read(networkmanager)
        MAC = Refactor.get_interface_mac(interface)
        if MAC != None and not Remove:
            if path.exists(networkmanager):
                try:
                    config.add_section('keyfile')
                except configparser.DuplicateSectionError, e:
                    config.set('keyfile','unmanaged-devices','mac:{}'.format(MAC))
                else:
                    config.set('keyfile','unmanaged-devices','mac:{}'.format(MAC))
                finally:
                    with open(networkmanager, 'wb') as configfile:
                        config.write(configfile)
                return True
        elif MAC != None and Remove:
            try:
                config.remove_option('keyfile','unmanaged-devices')
                with open(networkmanager, 'wb') as configfile:
                    config.write(configfile)
                    return True
            except configparser.NoSectionError:
                pass
        if not path.exists(networkmanager):
            return False

    @staticmethod
    def set_ip_forward(value):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
            file.write(str(value))
            file.close()
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    @staticmethod
    def getHwAddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = ioctl(s.fileno(), 0x8927,  pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

    @staticmethod
    def get_interfaces():
        interfaces = {'activated':None,'all':[],'gateway':None,'IPaddress':None}
        interfaces['all'] = netifaces.interfaces()
        try:
            interfaces['gateway'] = netifaces.gateways()['default'][netifaces.AF_INET][0]
            interfaces['activated'] = netifaces.gateways()['default'][netifaces.AF_INET][1]
            interfaces['IPaddress'] = Refactor.get_Ipaddr(interfaces['activated'])
        except KeyError:
            print('Error: find network interface information ')
        return interfaces

    @staticmethod
    def get_Ipaddr(card):
        if card == None:
            return get_if_addr(Refactor.get_interfaces()['activated'])
        return get_if_addr(card)

    @staticmethod
    def get_mac(host):
        fields = popen('grep "%s " /proc/net/arp' % host).read().split()
        if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
            return fields[3]
        else:
            return None

    @staticmethod
    def get_interface_mac(device):
        result = check_output(["ifconfig", device], stderr=STDOUT, universal_newlines=True)
        m = search("(?<=HWaddr\\s)(.*)", result)
        if not hasattr(m, "group") or m.group(0) == None:
            return None
        return m.group(0).strip()

    @staticmethod
    def randomMacAddress(prefix):
        for _ in xrange(6-len(prefix)):
            prefix.append(randint(0x00, 0x7f))
        return ':'.join('%02x' % x for x in prefix)


    @staticmethod
    def check_is_mac(value):
        checked = compile(r"""(
         ^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$
        |^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
        )""",VERBOSE|IGNORECASE)
        if checked.match(value) is None:return False
        else:
            return True
    @staticmethod
    def threadRoot(sudo_password):
        call(['sudo','-k'])
        p = Popen(['sudo', '-S','./wifi-pumpkin.py'], stdin=PIPE, stderr=PIPE,
        universal_newlines=True)
        waiter().start()
        p.communicate(str(sudo_password) + '\n')[1]

    @staticmethod
    def find(name, paths):
        for root, dirs, files in walk(paths):
            if name in files:
                return path.join(root, name)
    @staticmethod
    def getSize(filename):
        st = stat(filename)
        return st.st_size

class waiter(threading.Thread):
    def run(self):
        sleep(10)