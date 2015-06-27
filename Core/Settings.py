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
        self.loadtheme(self.XmlThemeSelected())
        self.Qui()

    def loadtheme(self,theme):
        if theme != "theme2":
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
        else:
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())

    def XmlThemeSelected(self):
        theme = self.xmlSettings("themes", "selected",None,False)
        return theme
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
        if self.theme1.isChecked():
            self.xmlSettings("themes","selected","theme1",False)
            QMessageBox.information(self,"select theme","You need to restart the app 3viltwinAttacker")
        elif self.theme2.isChecked():
            self.xmlSettings("themes","selected","theme2",False)
            QMessageBox.information(self,"select theme","You need to restart the app 3viltwinAttacker")
        if self.scan1.isChecked():
            self.xmlSettings("advanced","Function_scan","Ping",False)
        elif self.scan2.isChecked():
            self.xmlSettings("advanced","Function_scan","Nmap",False)
        self.txt_arguments.setText(self.xmlSettings("mdk3", "arguments", str(self.txt_arguments.text()), False))
        self.txt_ranger.setText(self.xmlSettings("scan","rangeIP",str(self.txt_ranger.text()),False))
        self.close()


    def Qui(self):
        self.form = QFormLayout(self)
        self.tabcontrol = QTabWidget(self)
        self.tab1 = QWidget(self)
        self.tab2 = QWidget(self)

        self.txt_ranger = QLineEdit(self)
        self.txt_arguments = QLineEdit(self)
        self.page_1 = QFormLayout(self.tab1)
        self.page_1.maximumSize()
        self.page_2 = QFormLayout(self.tab2)
        self.tabcontrol.addTab(self.tab1, "General")
        self.tabcontrol.addTab(self.tab2, "Advanced")

        self.title0 = QLabel("Configure deauth Attacker:")
        self.title1 = QLabel("Configure Dhcp Attacker:")
        self.title2 = QLabel("mdk3 Arguments:")
        self.title3 = QLabel("Configure Scan diveces Attacker:")
        self.title4 = QLabel("3vilTwinAttacker Themes:")
        self.title5 = QLabel("Configure Range ARP Posion:")

        self.title6 = QLabel("Thread ScanIP:")

        self.title0.isTopLevel()
        self.btn_save = QPushButton("Save")
        self.btn_save.clicked.connect(self.save_settings)
        self.btn_save.setFixedWidth(80)
        #icons
        self.btn_save.setIcon(QIcon("rsc/Save.png"))

        self.GruPag1=QButtonGroup()
        self.GruPag2=QButtonGroup()
        self.GruPag3=QButtonGroup()
        self.GruPag4=QButtonGroup()

        self.Grup2Page1 = QButtonGroup()


        #page 1
        self.d_scapy = QRadioButton("Scapy Deauth")
        self.d_mdk = QRadioButton("mdk3 Deauth")
        self.scan_scapy = QRadioButton("Scan from scapy")
        self.scan_airodump = QRadioButton("Scan from airodump-ng")
        self.dhcp1 = QRadioButton("iscdhcpserver")
        self.dhcp2 = QRadioButton("DNSmasq")
        self.dhcp2.setDisabled(True)
        self.theme1 = QRadioButton("theme Dark Orange")
        self.theme2 = QRadioButton("theme Dark blur")

        #page 2
        self.scan1 = QRadioButton("Ping Scan:: Very fast scan IP")
        self.scan2 = QRadioButton("Python-Nmap:: Get hostname from IP")

        #grup page 1
        self.GruPag1.addButton(self.d_scapy)
        self.GruPag1.addButton(self.d_mdk)
        self.GruPag2.addButton(self.dhcp1)
        self.GruPag2.addButton(self.dhcp2)
        self.GruPag3.addButton(self.scan_scapy)
        self.GruPag3.addButton(self.scan_airodump)
        self.GruPag4.addButton(self.theme1)
        self.GruPag4.addButton(self.theme2)

        # grup page 2
        self.Grup2Page1.addButton(self.scan1)
        self.Grup2Page1.addButton(self.scan2)


        self.scapy_check = self.xmlSettings("item0","deauth_scapy",None,False)
        self.mdk3_check = self.xmlSettings("item1","deauth_mdk3",None,False)
        self.scan_scapy_check = self.xmlSettings("monitor0", "scan_scapy", None, False)
        self.scan_air_check = self.xmlSettings("monitor1", "scan_airodump", None,False)
        self.dhcp1_check = self.xmlSettings("item2", "iscdhcpserver", None, False)
        self.dhcp2_check = self.xmlSettings("item3", "dnsmasq", None, False)
        self.txt_ranger.setText(self.xmlSettings("scan", "rangeIP", None, False))
        self.txt_arguments.setText(self.xmlSettings("mdk3", "arguments", None, False))

        self.scanIP_selected  = self.xmlSettings("advanced","Function_scan",None,False)
        if self.scanIP_selected == "Ping":
            self.scan1.setChecked(True)
            self.scan2.setChecked(False)
        elif self.scanIP_selected == "Nmap":
            self.scan2.setChecked(True)
            self.scan1.setChecked(False)

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

        self.theme_selected = self.xmlSettings("themes", "selected", None, False)
        if self.theme_selected == "theme1":
            self.theme1.setChecked(True)
        else:
            self.theme2.setChecked(True)

        self.page_1.addWidget(self.title0)
        self.page_1.addWidget(self.d_scapy)
        self.page_1.addWidget(self.d_mdk)

        self.page_1.addWidget(self.title3)
        self.page_1.addWidget(self.scan_scapy)
        self.page_1.addWidget(self.scan_airodump)

        self.page_1.addWidget(self.title2)
        self.page_1.addWidget(self.txt_arguments)

        self.page_1.addWidget(self.title1)
        self.page_1.addWidget(self.dhcp1)
        self.page_1.addWidget(self.dhcp2)

        self.page_1.addWidget(self.title5)
        self.page_1.addWidget(self.txt_ranger)

        self.page_1.addWidget(self.title4)
        self.page_1.addWidget(self.theme1)
        self.page_1.addWidget(self.theme2)

        #page 2
        self.page_2.addWidget(self.title6)
        self.page_2.addWidget(self.scan1)
        self.page_2.addWidget(self.scan2)

        self.form.addRow(self.tabcontrol)
        self.form.addRow(self.btn_save)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)
