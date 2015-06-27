from PyQt4.QtGui import *
from re import search
from os import system,geteuid,getuid
from Core.Settings import frm_Settings
from subprocess import Popen,PIPE
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from Core.Main import  frm_dhcp_Attack


class frm_Probe(QMainWindow):
    def __init__(self, parent=None):
        super(frm_Probe, self).__init__(parent)
        self.form_widget = frm_PMonitor(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowIcon(QIcon('rsc/icon.ico'))
    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About Exit',"Are you sure to quit?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            if getuid() == 0:
                system("airmon-ng stop mon0")
                system("clear")
                self.deleteLater()
            else:
                pass
        else:
            event.ignore()

class frm_PMonitor(QWidget):
    def __init__(self, parent=None):
        super(frm_PMonitor, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.setWindowTitle("Probe Request wifi Monitor")
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.interface = "mon0"
        self.probes = []
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.setupGUI()
    def loadtheme(self,theme):
        if theme != "theme2":
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
        else:
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())

    def setupGUI(self):
        self.form0 = QFormLayout()
        self.list_probe = QListWidget()
        self.list_probe.setFixedHeight(400)
        self.btn_scan = QPushButton("Scan")
        self.btn_scan.clicked.connect(self.Pro_request)
        self.btn_scan.setIcon(QIcon("rsc/network.png"))
        self.get_placa = QComboBox(self)
        Interfaces = frm_dhcp_Attack()
        n = Interfaces.placa()
        for i,j in enumerate(n):
            if search("wlan", j):
                self.get_placa.addItem(n[i])

        self.time_scan = QComboBox(self)
        self.time_scan.addItem("10s")
        self.time_scan.addItem("20s")
        self.time_scan.addItem("30s")

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
        if self.time_scan.currentText() == "10s":
            self.time_control = 300
        elif self.time_scan.currentText() == "20s":
            self.time_control = 400
        elif self.time_scan.currentText() == "30s":
            self.time_control = 600
        if self.get_placa.currentText() == "":
            QMessageBox.information(self, "Network Adapter", 'Network Adapter Not found try again.')
        else:
            if not geteuid() == 0:
                QMessageBox.information(self, "Permission Denied", 'the tool must be run as root try again.')
            else:
                comando = "ifconfig"
                proc = Popen(comando,stdout=PIPE, shell=True)
                data = proc.communicate()[0]
                if search("mon0", data):
                    sniff(iface=self.interface,prn=self.sniff_probe, count=self.time_control)
                    system("clear")
                else:
                    system("airmon-ng start %s" %(self.get_placa.currentText()))
                    sniff(iface=self.interface,prn=self.sniff_probe, count=self.time_control)
                    system("clear")

    def sniff_probe(self,p):
        if (p.haslayer(Dot11ProbeReq)):
                mac_address=(p.addr2)
                ssid=p[Dot11Elt].info
                ssid=ssid.decode('utf-8','ignore')
                if ssid == "":
                        ssid="null"
                else:
                        print ("[:] Probe Request from %s for SSID '%s'" %(mac_address,ssid))
                        self.probes.append("[:] Probe Request from %s for SSID '%s'" %(mac_address,ssid))
                        self.list_probe.addItem("[:] Probe Request from %s for SSID '%s'" %(mac_address,ssid))