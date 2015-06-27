from PyQt4.QtGui import *
from PyQt4.QtCore import *
from re import search
from os import geteuid,popen
from subprocess import Popen,PIPE
from Core.Settings import frm_Settings
import subprocess
import random
class frm_mac_changer(QMainWindow):
    def __init__(self, parent=None):
        super(frm_mac_changer, self).__init__(parent)
        self.form_widget = frm_mac_generator(self)
        self.setCentralWidget(self.form_widget)

class frm_mac_generator(QWidget):
    def __init__(self, parent=None):
        super(frm_mac_generator, self).__init__(parent)
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.setWindowIcon(QIcon('Modules/icon.ico'))
        self.setWindowTitle("MAC Address Generator")
        self.Main = QVBoxLayout()
        self.prefix = [ 0x00, 0xCB, 0x01,0x03 ,\
                        0x84,0x78,0xAC, 0x88,0xD3,\
                        0x7B, 0x8C,0x7C,0xB5, 0x90,0x99,0x16, \
                        0x9C, 0x6A ,0xBE , 0x55, 0x12, 0x6C , 0xD2,\
                        0x8b, 0xDA, 0xF1, 0x9c , 0x20 , 0x3A, 0x4A,\
                        0x2F, 0x31, 0x32, 0x1D, 0x5F, 0x70, 0x5A,\
                        0x5B, 0x5C, 0x63, 0x4F, 0x3F, 0x5F, 0x9E]

        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.MacGUI()
    def loadtheme(self,theme):
        if theme != "theme2":
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
        else:
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
    def get_interface_mac(self,device):
        result = subprocess.check_output(["ifconfig", device], stderr=subprocess.STDOUT, universal_newlines=True)
        m = search("(?<=HWaddr\\s)(.*)", result)
        if not hasattr(m, "group") or m.group(0) == None:
            return None
        return m.group(0).strip()

    def placa(self):
        comando = "ls -1 /sys/class/net"
        proc = Popen(comando,stdout=PIPE, shell=True)
        data = proc.communicate()[0]
        return  data.split('\n')

    @pyqtSlot(QModelIndex)
    def combo_clicked(self, device):
        if device == "":
            self.i_mac.setText('Not Found')
        else:
            self.i_mac.setText(self.get_interface_mac(device))
    def randomMacAddress(self,prefix):
        for _ in xrange(6-len(prefix)):
            prefix.append(random.randint(0x00, 0x7f))
        return ':'.join('%02x' % x for x in prefix)
    def action_btn_random(self):
        mac = self.randomMacAddress([random.choice(self.prefix) , random.choice(self.prefix) , random.choice(self.prefix)])
        self.i_mac.setText(mac)

    def setMAC(self,device,mac):
        subprocess.check_call(["ifconfig","%s" % device, "up"])
        subprocess.check_call(["ifconfig","%s" % device, "hw", "ether","%s" % mac])

    def change_macaddress(self):
        if not geteuid() == 0:
            QMessageBox.information(self, "Permission Denied", 'Tool must be run as root try again.')
        else:
            self.setMAC(self.combo_card.currentText(), self.i_mac.text())
            self.deleteLater()
    def MacGUI(self):
        self.form_mac = QFormLayout()
        self.i_mac = QLineEdit(self)
        self.combo_card = QComboBox(self)
        self.btn_random = QPushButton("Random MAC")
        self.btn_random.setIcon(QIcon("rsc/refresh.png"))
        self.btn_save = QPushButton("Save")
        self.btn_save.setIcon(QIcon("rsc/Save.png"))
        self.btn_save.clicked.connect(self.change_macaddress)
        self.btn_random.clicked.connect(self.action_btn_random)
        self.n = self.placa()
        self.combo_card.addItems(self.n)
        self.connect(self.combo_card, SIGNAL('activated(QString)'), self.combo_clicked)
        self.form_mac.addRow(self.combo_card,self.i_mac)
        self.form_mac.addRow("MAC Random: ", self.btn_random)
        self.form_mac.addRow(self.btn_save)
        self.Main.addLayout(self.form_mac)
        self.setLayout(self.Main)

class frm_GetIP(QWidget):
    def __init__(self, parent=None):
        super(frm_GetIP, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.setWindowIcon(QIcon('Modules/icon.ico'))
        self.setWindowTitle("Device fingerprint wireless network")
        self.listGUI()
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
                    if not geteuid() == 0:
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
        self.btn_scan.clicked.connect(self.get_clients)
        self.label1 = QLabel("IPAddress")
        self.label2 = QLabel("     | MACAddress      |   OS")
        self.form0.addRow(self.label1, self.label2)
        self.form0.addRow(self.lb_clients)
        self.form0.addRow("You Need Root:", self.cb_getOS)
        self.form0.addRow(self.btn_scan)
        self.Main.addLayout(self.form0)
        self.setLayout(self.Main)