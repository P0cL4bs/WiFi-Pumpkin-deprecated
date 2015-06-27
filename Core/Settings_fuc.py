from PyQt4.QtGui import *
from xml.dom import minidom
class frm_Settings(QDialog):
    def __init__(self, parent = None):
        super(frm_Settings, self).__init__(parent)
        self.setWindowTitle("Settings 3vilTwinAttacker")
        self.Main = QVBoxLayout()
        self.frm = QFormLayout()
        self.setGeometry(0, 0, 400, 300)
        self.center()
        sshFile="Core/dark_style.css"
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())
        self.Qui()
    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def xmlSettings(self,id,data,bool,show):
        xmldoc = minidom.parse('Settings/Settings.xml')
        country = xmldoc.getElementsByTagName(id)
        firstchild = country[0]
        if bool != None:
            firstchild.attributes[data].value = bool
        if show == True:
            print "---------------------------"
            print "Settings:" + data + "=>"+ firstchild.attributes[data].value
            print "---------------------------"
        xmldoc.writexml( open('Settings/Settings.xml', 'w'))

        return firstchild.attributes[data].value

    def save_settings(self):
        if self.d_scapy.isChecked():
            self.xmlSettings("item1","deauth_mdk3","False",False)
            self.xmlSettings("item0","deauth_scapy","True",False)
        elif self.d_mdk.isChecked():
            self.xmlSettings("item0","deauth_scapy","False",False)
            self.xmlSettings("item1","deauth_mdk3","True",False)
        if self.scan_scapy.isChecked():
            self.xmlSettings("monitor1", "scan_airodump", "False",False)
            self.xmlSettings("monitor0", "scan_scapy", "True", False)
        elif self.scan_airodump.isChecked():
            self.xmlSettings("monitor0", "scan_scapy", "False", False)
            self.xmlSettings("monitor1", "scan_airodump", "True",False)
        if self.dhcp1.isChecked():
            self.xmlSettings("item3","dnsmasq","False",False)
            self.xmlSettings("item2","iscdhcpserver","True",False)
        elif self.dhcp2.isChecked():
            self.xmlSettings("item2","iscdhcpserver","False",False)
            self.xmlSettings("item3","dnsmasq","True",False)
        self.txt_arguments.setText(self.xmlSettings("mdk3", "arguments", str(self.txt_arguments.text()), False))
        self.txt_ranger.setText(self.xmlSettings("scan","rangeIP",str(self.txt_ranger.text()),False))
        self.deleteLater()

    def Qui(self):
        self.tabcontrol = QTabWidget(self)
        self.tab1 = QWidget(self)
        self.tab2 = QWidget(self)

        self.txt_arguments = QLineEdit(self)
        self.txt_ranger = QLineEdit(self)
        self.page_1 = QFormLayout(self.tab1)
        self.page_1.maximumSize()
        self.page_2 = QFormLayout(self.tab2)
        self.tabcontrol.addTab(self.tab1, "General")
        self.tabcontrol.addTab(self.tab2, "Advanced")

        self.title = QLabel("Configure deauth Attacker:")
        self.title1 = QLabel("Configure Dhcp Attacker:")
        self.title3 = QLabel("Configure Range ARP Posion:")
        self.title4 = QLabel("Configure Scan diveces Attacker:")
        self.title2 = QLabel("mdk3 Arguments:")
        self.title.isTopLevel()
        self.btn_save = QPushButton("Save")
        self.btn_save.clicked.connect(self.save_settings)
        self.btn_save.setFixedWidth(80)

        #icons
        self.btn_save.setIcon(QIcon("rsc/Save.png"))

        self.grup1=QButtonGroup()
        self.grup2=QButtonGroup()
        self.grup3=QButtonGroup()

        self.d_scapy = QRadioButton("Scapy Deauth")
        self.d_mdk = QRadioButton("mdk3 Deauth")
        self.scan_scapy = QRadioButton("Scan from scapy")
        self.scan_airodump = QRadioButton("Scan from airodump-ng")

        self.dhcp1 = QRadioButton("iscdhcpserver")
        self.dhcp2 = QRadioButton("DNSmasq")
        self.dhcp2.setDisabled(True)

        self.grup1.addButton(self.d_scapy)
        self.grup1.addButton(self.d_mdk)
        self.grup3.addButton(self.scan_scapy)
        self.grup3.addButton(self.scan_airodump)

        self.grup2.addButton(self.dhcp1)
        self.grup2.addButton(self.dhcp2)




        self.scapy_check = self.xmlSettings("item0","deauth_scapy",None,False)
        self.mdk3_check = self.xmlSettings("item1","deauth_mdk3",None,False)

        self.scan_scapy_check = self.xmlSettings("monitor0", "scan_scapy", None, False)
        self.scan_air_check = self.xmlSettings("monitor1", "scan_airodump", None,False)

        self.dhcp1_check = self.xmlSettings("item2", "iscdhcpserver", None, False)
        self.dhcp2_check = self.xmlSettings("item3", "dnsmasq", None, False)
        self.txt_arguments.setText(self.xmlSettings("mdk3", "arguments", None, False))
        self.txt_ranger.setText(self.xmlSettings("scan", "rangeIP", None, False))

        if not self.scapy_check ==  "True":
            if not self.mdk3_check == "False":
                self.d_mdk.setChecked(True)
        else:
            self.d_scapy.setChecked(True)

        if not self.dhcp1_check == "True":
            if not self.dhcp2_check == "False":
                self.dhcp2.setChecked(True)
        else:
            self.dhcp1.setChecked(True)

        if not self.scan_scapy_check ==  "True":
            if not self.scan_air_check == "False":
                self.scan_airodump.setChecked(True)
        else:
            self.scan_scapy.setChecked(True)

        self.page_1.addWidget(self.title)
        self.page_1.addWidget(self.d_scapy)
        self.page_1.addWidget(self.d_mdk)
        self.page_1.addWidget(self.title4)
        self.page_1.addWidget(self.scan_scapy)
        self.page_1.addWidget(self.scan_airodump)

        self.page_1.addWidget(self.title2)
        self.page_1.addWidget(self.txt_arguments)

        self.page_1.addWidget(self.title1)
        self.page_1.addWidget(self.dhcp1)
        self.page_1.addWidget(self.dhcp2)

        self.page_1.addWidget(self.title3)
        self.page_1.addWidget(self.txt_ranger)


        self.page_1.addWidget(self.btn_save)
        self.next = QLabel("wait... next version :)")
        self.page_2.addWidget(self.next)
        self.Main.addWidget(self.tabcontrol)
        self.setLayout(self.Main)
