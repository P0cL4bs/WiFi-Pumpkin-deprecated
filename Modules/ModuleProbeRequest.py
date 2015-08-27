#The MIT License (MIT)
#Copyright (c) 2015-2016 mh4x0f P0cL4bs Team
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in
#the Software without restriction, including without limitation the rights to
#use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
#the Software, and to permit persons to whom the Software is furnished to do so,
#subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
#FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
from PyQt4.QtGui import *
from re import search
from os import system,geteuid,getuid,popen
from Core.Settings import frm_Settings
from Modules.utils import Refactor,set_monitor_mode
from subprocess import Popen,PIPE
from scapy.all import *


class frm_Probe(QMainWindow):
    def __init__(self, parent=None):
        super(frm_Probe, self).__init__(parent)
        self.form_widget = frm_PMonitor(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowIcon(QIcon('rsc/icon.ico'))

class frm_PMonitor(QWidget):
    def __init__(self, parent=None):
        super(frm_PMonitor, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.setWindowTitle("Probe Request wifi Monitor")
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.config = frm_Settings()
        self.interface = str(self.config.xmlSettings("interface", "monitor_mode", None, False))
        self.loadtheme(self.config.XmlThemeSelected())
        self.setupGUI()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def setupGUI(self):
        self.form0 = QFormLayout()
        self.list_probe = QListWidget()
        self.list_probe.setFixedHeight(300)
        self.btn_scan = QPushButton("Scan")
        self.btn_scan.clicked.connect(self.Pro_request)
        self.btn_scan.setIcon(QIcon("rsc/network.png"))
        self.get_placa = QComboBox(self)
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search("wlan", j):
                self.get_placa.addItem(n[i])

        self.time_scan = QComboBox(self)
        self.time_scan.addItems(["10s","20s","30s"])

        self.form0.addRow("Network Adapter: ", self.get_placa)
        self.form0.addRow(self.list_probe)
        self.form0.addRow("Time Scan: ", self.time_scan)
        self.form1 = QFormLayout()
        self.form1.addRow(self.btn_scan)
        self.Main.addLayout(self.form0)
        self.Main.addLayout(self.form1)

        self.setLayout(self.Main)
    def Pro_request(self):
        self.time_control = None
        if self.time_scan.currentText() == "10s":self.time_control = 300
        elif self.time_scan.currentText() == "20s":self.time_control = 400
        elif self.time_scan.currentText() == "30s":self.time_control = 600
        if self.get_placa.currentText() == "":
            QMessageBox.information(self, "Network Adapter", 'Network Adapter Not found try again.')
            return
        out = popen('iwconfig').readlines()
        for i in out:
            if search('Mode:Monitor', i):
                self.interface = i.split()[0]
                sniff(iface=self.interface,prn=self.sniff_probe, count=self.time_control)
                return
        set_monitor_mode(self.get_placa.currentText()).setEnable()
        sniff(iface=self.interface,prn=self.sniff_probe, count=self.time_control)

    def sniff_probe(self,p):
        if (p.haslayer(Dot11ProbeReq)):
                mac_address=(p.addr2)
                ssid=p[Dot11Elt].info
                ssid=ssid.decode('utf-8','ignore')
                if ssid == "":ssid="null"
                self.list_probe.addItem("[:] Probe Request from %s for SSID '%s'" %(mac_address,ssid))