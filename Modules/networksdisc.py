#coding: utf-8
from PyQt4.QtGui import *
from os import getegid,popen
from re import search
from Core.Settings import frm_Settings
from scapy.all import *

class frm_list_IP(QMainWindow):
    def __init__(self, parent=None):
        super(frm_list_IP, self).__init__(parent)
        self.form_widget = frm_GetIP(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowIcon(QIcon('rsc/icon.ico'))

class frm_GetIP(QWidget):
    def __init__(self, parent=None):
        super(frm_GetIP, self).__init__(parent)
        self.setWindowTitle("Device fingerprint wireless network")
        self.Main = QVBoxLayout()
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.listGUI()
    def loadtheme(self,theme):
        if theme != "theme2":
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
        else:
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())

    def get_clients(self):
        output =  popen("route | grep default ")
        conf =  output.read().split()
        if conf != []:
            conf = conf[1]
            getway_default = conf[:len(conf)-1] + "*"
            self.nmap_get_ip(getway_default)
        else:
            QMessageBox.information(self, "Network Error", 'You need be connected the internet try again.')
    def get_mac(self,host):
        fields = popen('grep "%s " /proc/net/arp' % host).read().split()
        if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
            return fields[3]
        else:
            return ' not detected'
    def get_OS(self, ipaddress):
        output =  popen("route | grep default ")
        conf =  output.read().split()
        if conf != []:
            route = conf[1]
            if ipaddress != route:
                data = popen("nmap -A -O -Pn %s | grep 'OS'"%(ipaddress)).read()
                if search(":microsoft:windows_7", data):
                    file = popen("nmap -A -sV -O %s | grep 'NetBIOS computer name'"%(ipaddress)).read().split()
                    return " Windows 2008|7|Phone|Vista | PC Name: " + file[4]
                elif search("Apple", data):
                    return " Iphone Or MAC oS"
                elif search("linux",data):
                    if search(":android:", data):
                        return " Android"
                    else:
                        return " Linux"
                elif search("", data):
                    return "OS Unknown"
            else:
                return "Router"
        else:
            QMessageBox.information(self, "Network Error", 'You need be connected the internet try again.')


    def nmap_get_ip(self,geteway):
        self.lb_clients.clear()
        self.setStyleSheet('QListWidget {color: yellow}')
        clients = popen("nmap -sP "+ geteway)
        c = clients.read().split()
        for i,j in enumerate(c):
            if j.count(".") == 3:
                if self.cb_getOS.isChecked():
                    if not getegid() == 0:
                        QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                        break
                    else:
                        self.lb_clients.addItem(c[i] + "| " + str(self.get_mac(c[i]) + "|" + str(self.get_OS(c[i]))))
                else:
                    self.lb_clients.addItem(c[i] + "| " + str(self.get_mac(c[i])))
    def listGUI(self):
        self.form0 = QFormLayout()
        self.lb_clients = QListWidget(self)
        self.cb_getOS = QCheckBox("Detect OS")
        self.btn_scan = QPushButton("Scan Clients")
        self.btn_scan.setIcon(QIcon("rsc/network.png"))
        self.btn_scan.clicked.connect(self.get_clients)
        self.label1 = QLabel("IPAddress")
        self.label2 = QLabel("     | MACAddress      |   OS")
        self.form0.addRow(self.label1, self.label2)
        self.form0.addRow(self.lb_clients)
        self.form0.addRow("You Need Root:", self.cb_getOS)
        self.form0.addRow(self.btn_scan)
        self.Main.addLayout(self.form0)
        self.setLayout(self.Main)
