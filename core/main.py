from logging import getLogger,ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from PyQt4 import QtGui
from PyQt4 import QtCore
from json import dumps,loads
from time import asctime
from shutil import move
from re import search
from os import path,popen,mkdir
from subprocess import Popen,PIPE

from core.utils import (
    Refactor,set_monitor_mode,
    waiterSleepThread,exec_bash,del_item_folder
)

from core.utility.threads import ThreadReactor,ThreadPopen
import modules as GUIModules
from core.helpers.about import frmAbout
from core.helpers.update import frm_githubUpdate
from core.utility.settings import frm_Settings
import core.utility.constants as C
from core.helpers.update import ProgressBarWid
from core.helpers.report import frm_ReportLogger
from core.widgets.notifications import ServiceNotify
from netfilterqueue import NetfilterQueue
from core.widgets.default import *
from core.defaultwidget import *

from core.controllers.wirelessmodecontroller import *
from core.controllers.dnscontroller import *
from core.controllers.dhcpcontroller import *
from core.controllers.proxycontroller import *
from core.controllers.mitmcontroller import *
from core.servers.dhcp.dhcp import *

approot = QtCore.QCoreApplication.instance()



"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for mount Access point.

Copyright:
    Copyright (C) 2015-2019 Marcos Bomfim (Nesster) P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""


author      = 'Marcos Nesster (@mh4x0f)  P0cl4bs Team'
emails      = ['mh4root@gmail.com','p0cl4bs@gmail.com']
license     = ' GNU GPL 3'
version     = '0.8.8'
update      = '04/06/2019'
desc        = ['Framework for Rogue Wi-Fi Access Point Attacks']

class Initialize(QtGui.QMainWindow):
    ''' Main window settings multi-window opened'''
    def __init__(self, parent=None):
        super(Initialize, self).__init__(parent)
        self.FSettings      = frm_Settings.instances[0]
        self.UI    = WifiPumpkin(self)

        #for exclude USB adapter if the option is checked in settings tab
        self.networkcontrol = None
        # create advanced mode support
        dock = QtGui.QDockWidget()
        dock.setTitleBarWidget(QtGui.QWidget())
        dock.setWidget(self.UI)
        dock.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        dock.setFeatures(QtGui.QDockWidget.NoDockWidgetFeatures)
        dock.setAllowedAreas(QtCore.Qt.AllDockWidgetAreas)
        self.addDockWidget(QtCore.Qt.LeftDockWidgetArea, dock)
        # set window title
        self.setWindowTitle('WiFi-Pumpkin v' + version)
        self.setGeometry(0, 0, C.GEOMETRYH, C.GEOMETRYW) # set geometry window
        self.loadtheme(self.FSettings.get_theme_qss())

    def passSettings(self):
        global approot
        #self.FSettings = approot.Settings
        #print self.FSettings

    def loadtheme(self,theme):
        ''' load Theme from file .qss '''
        sshFile=("core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        ''' set Window center desktop '''
        frameGm = self.frameGeometry()
        centerPoint = QtGui.QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def closeEvent(self, event):
        ''' When the user clicks on the X button '''
        if self.UI.THReactor.isReactorRunning:
            self.UI.THReactor.stop()
        if self.UI.THReactor.isRunning():
            self.UI.THReactor.stop()

        # remove card apdater from network-manager conf
        if not self.FSettings.Settings.get_setting(
            'accesspoint','persistNetwokManager',format=bool):
            if self.networkcontrol != None:
                self.networkcontrol.remove_settingsNM()

        # check if any wireless card is enable as Monitor mode
        iwconfig = Popen(['iwconfig'], stdout=PIPE,shell=False,stderr=PIPE)
        for i in iwconfig.stdout.readlines():
            if search('Mode:Monitor',i):
                self.reply = QtGui.QMessageBox.question(self,
                'About Exit','Are you sure to quit?', QtGui.QMessageBox.Yes |
                QtGui.QMessageBox.No, QtGui.QMessageBox.No)
                if self.reply == QtGui.QMessageBox.Yes:
                    set_monitor_mode(i.split()[0]).setDisable()
                    return event.accept()
                return event.ignore()

        # check is Rouge AP is running
        if self.UI.Apthreads['RogueAP'] != []:
            self.reply = QtGui.QMessageBox.question(self,
            'About Access Point','Are you sure to stop all threads AP ?', QtGui.QMessageBox.Yes |
            QtGui.QMessageBox.No, QtGui.QMessageBox.No)
            if self.reply == QtGui.QMessageBox.Yes:
                print('killing all threads...')
                self.UI.stop_access_point()
                return event.accept()
            return event.ignore()
        return event.accept()

class WifiPumpkin(QtGui.QWidget):
    ''' load main window class'''
    currentSessionID = ""
    instances=[]
    Apthreads = {'RogueAP': []}
    SettingsEnable = {
        'ProgCheck': [],
        'AP_iface': None,
        'PortRedirect': None,
        'interface': 'None',
    }
    APclients = {}
    SettingsAP = {}
    SessionsAP = {}

    def __init__(self, mainWindow):
        super(WifiPumpkin,self).__init__()
        self.__class__.instances.append(weakref.proxy(self))
        self.mainWindow = mainWindow
        self.InternetShareWiFi = True # share internet options


        # check update from github repository
        self.Timer = waiterSleepThread()
        self.Timer.quit.connect(self.get_status_new_commits)
        self.UpdateSoftware = frm_githubUpdate(version)
        self.UpdateSoftware.resize(480, 280)
        self.UpdateSoftware.show()
        self.UpdateSoftware.setHidden(True)
        self.UpdateSoftware.checkUpdate()
        self.Timer.start()

        self.status_plugin_proxy_name = QtGui.QLabel('')  # status name proxy activated

        # define all Widget TABs
        self.MainControl    = QtGui.QVBoxLayout()
        self.TabControl     = QtGui.QTabWidget()
        #self.Tab_Plugins    = QtGui.QWidget()
        self.Tab_dock       = QtGui.QMainWindow() # for dockarea
        self.FSettings      = self.mainWindow.FSettings
        self.LeftTabBar = QtGui.QListWidget()
        self.Stack = QtGui.QStackedWidget(self)
        self.Stack.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)

        # create dockarea in Widget class
        self.dock = QtGui.QDockWidget()
        self.dock.setTitleBarWidget(QtGui.QWidget())
        self.dock.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.dock.setFeatures(QtGui.QDockWidget.NoDockWidgetFeatures)
        self.dock.setAllowedAreas(QtCore.Qt.AllDockWidgetAreas)


        #TODO This is a new Implementation to simplify development
        self.coreui = DefaultWidget(self)
        self.wireless = WirelessModeController(self)
        self.dnsserver = DNSController(self)
        self.dnsDockList = []
        self.dnsserver.dockMount.connect(self.dnsDockAdd)

        self.proxy = self.coreui.Plugins.Proxy
        self.proxy.dockMount.connect(self.proxyDockAdd)
        self.proxyDocklist = []
        self.mitmhandler = self.coreui.Plugins.MITM
        self.mitmDockList=[]
        self.AreaDockInfo=[]
        self.mitmhandler.dockMount.connect(self.mitmDockAdd)

        #TODO Might need improvement, checking if the program needed are installed

        lista = ['', '',
                 popen('which driftnet').read().split('\n')[0],
                 popen('which dhcpd').read().split("\n")[0], '',
                 popen('which hostapd').read().split("\n")[0],
                 popen('which xterm').read().split("\n")[0]
                 ]
        for i in lista: self.SettingsEnable['ProgCheck'].append(path.isfile(i))

        self.LeftTabBar.currentRowChanged.connect(self.set_index_leftMenu)
        self.LeftTabBar.setFixedWidth(170)
        self.LeftTabBar.setStyleSheet(C.MENU_STYLE)
        # add in Tab default widget TABs

        

        self.SessionsAP     = loads(str(self.FSettings.Settings.get_setting('accesspoint','sessions')))

        self.THReactor = ThreadReactor() # thread reactor for sslstrip
        self.window_phishing = GUIModules.frm_PhishingManager()
        # TODO Refactored default widget
        self.index = 0
        indexpass = False
        for v in sorted(self.coreui.allui):
            if v.Name == "Home":
                indexpass =True

            self.LeftTabBar.addItem(v.tabinterface)
            self.Stack.addWidget(v)
            setattr(self, v.ID, v)
            if not indexpass:
                self.index+=1
        # self.proxy.sendSingal_disable.connect(self.get_disable_proxy_status)
        self.proxy.SetNoProxy.connect(self.
                                      get_disable_proxy_status)
        #TODO DHCP Configuration Definition
        for v in self.proxy.get.values():
            if not v.Hidden:
                self.LeftTabBar.addItem(v.tabinterface)
                self.Stack.addWidget(v)
            if self.proxy.isChecked():
                # v.sendSingal_disable.connect(self.get_disable_proxy_status)
                if v.controlui.isChecked():
                    if v.Name == "No Proxy":
                        self.set_proxy_statusbar('', disabled=True)
                        v.sendSingal_disable.emit(v.controlui.isChecked())
                    else:
                        self.set_proxy_statusbar(v.Name)
            else:
                self.set_proxy_statusbar('', disabled=True)
                v.sendSingal_disable.emit(v.controlui.isChecked())
        self.DHCP = self.SessionConfig.DHCP.conf
        self.dhcpcontrol = DHCPController(self)
        self.updateSettingsAP() # create settings ap on startup
        self.initial_GUI_loader()
        self.proxy.Active.dockwidget.addDock.emit(self.proxy.Active.controlui.isChecked())
        for mitm in self.mitmhandler.Active:
            mitm.dockwidget.addDock.emit(mitm.controlui.isChecked())
        self.DockArrage()

    def updateSettingsAP(self):
        self.DHCP = self.SessionConfig.DHCP.conf
        self.SettingsAP = {
            'interface':
                [
                    'ifconfig %s up' % (self.SessionConfig.Wireless.WLANCard.currentText()),
                    'ifconfig %s %s netmask %s' % (
                        self.SessionConfig.Wireless.WLANCard.currentText(),
                        self.DHCP['router'],
                        self.DHCP['netmask']),
                    'ifconfig %s mtu 1400' % (self.SessionConfig.Wireless.WLANCard.currentText()),
                    'route add -net %s netmask %s gw %s' % (self.DHCP['subnet'],
                                                            self.DHCP['netmask'], self.DHCP['router'])
                ],
            'kill':
                [
                    'iptables --flush',
                    'iptables --table nat --flush',
                    'iptables --delete-chain',
                    'iptables --table nat --delete-chain',
                    'ifconfig %s 0' % (self.SessionConfig.Wireless.WLANCard.currentText()),
                    'killall dhpcd 2>/dev/null',
                ],
            'hostapd':
                [
                    'interface={}\n'.format(str(self.SessionConfig.Wireless.WLANCard.currentText())),
                    'ssid={}\n'.format(str(self.SessionConfig.Wireless.EditSSID.text())),
                    'channel={}\n'.format(str(self.SessionConfig.Wireless.EditChannel.value())),
                    'bssid={}\n'.format(str(self.SessionConfig.Wireless.EditBSSID.text())),
                ],
            'dhcp-server':
                [
                    'authoritative;\n',
                    'default-lease-time {};\n'.format(self.DHCP['leasetimeDef']),
                    'max-lease-time {};\n'.format(self.DHCP['leasetimeMax']),
                    'subnet %s netmask %s {\n' % (self.DHCP['subnet'], self.DHCP['netmask']),
                    'option routers {};\n'.format(self.DHCP['router']),
                    'option subnet-mask {};\n'.format(self.DHCP['netmask']),
                    'option broadcast-address {};\n'.format(self.DHCP['broadcast']),
                    'option domain-name \"%s\";\n' % (str(self.SessionConfig.Wireless.EditSSID.text())),
                    'option domain-name-servers {};\n'.format('8.8.8.8'),
                    'range {};\n'.format(self.DHCP['range'].replace('/', ' ')),
                    '}',
                ],
        }

    def mitmDockAdd(self,adding=True):
        for dck in self.mitmDockList:
            dck.close()
            self.ActivityMonitor.Dock.removeDockWidget(dck)
        self.mitmDockList=[]
        self.mitmDockList.extend(self.mitmhandler.ActiveDock)
        self.DockArrage()

    def dnsDockAdd(self,adding=True):
        for dck in self.dnsDockList:
            dck.close()
            self.ActivityMonitor.Dock.removeDockWidget(dck)
        self.dnsDockList=[]
        self.dnsDockList.insert(0,self.dnsserver.Active.dockwidget)
        self.DockArrage()

    def proxyDockAdd(self,adding=True):
        for dck in self.proxyDocklist:
            dck.close()
            self.ActivityMonitor.Dock.removeDockWidget(dck)
        self.proxyDocklist=[]
        self.proxyDocklist.insert(0, self.proxy.Active.dockwidget)
        self.DockArrage()


    def DockArrage(self):
        #TODO Find how to refresh dockarea
        self.AreaDockInfo=[]
        self.AreaDockInfo.insert(0,self.proxyDocklist[0])
        self.AreaDockInfo.extend(self.dnsDockList)
        self.AreaDockInfo.extend(self.mitmDockList)
        for dock in self.AreaDockInfo:
            self.ActivityMonitor.Dock.addDockWidget(QtCore.Qt.LeftDockWidgetArea, dock)
            dock.show()
        if len(self.AreaDockInfo) > 1:
            for index in range(1, len(self.AreaDockInfo) - 1):
                self.ActivityMonitor.Dock.tabifyDockWidget(self.AreaDockInfo[index],
                                                           self.AreaDockInfo[index + 1])
        self.AreaDockInfo[0].raise_()

    def initial_GUI_loader(self):
        ''' configure GUI default window '''
        self.SetupUI()

        self.myQMenuBar = QtGui.QMenuBar(self)
        Menu_file = self.myQMenuBar.addMenu('&File')
        exportAction = QtGui.QAction('Report Logger...', self)
        deleteAction = QtGui.QAction('Clear Logger', self)
        deleteAction.setIcon(QtGui.QIcon('icons/delete.png'))
        exportAction.setIcon(QtGui.QIcon('icons/export.png'))
        Menu_file.addAction(exportAction)
        Menu_file.addAction(deleteAction)
        deleteAction.triggered.connect(self.clean_all_loggers)

        exportAction.triggered.connect(self.show_exportlogger)
        action_settings = QtGui.QAction('Settings...',self)
        Menu_file.addAction(action_settings)

        Menu_View = self.myQMenuBar.addMenu('&View')
        self.statusap_action = QtGui.QAction('Status Dashboard', self.myQMenuBar, checkable=True)
        self.statusap_action.setChecked(self.FSettings.Settings.get_setting('settings',
        'show_dashboard_info', format=bool))
        self.check_status_ap_dashboard()
        #connect
        self.statusap_action.triggered.connect(self.check_status_ap_dashboard)

        Menu_View.addAction(self.statusap_action)

        #tools Menu
        Menu_tools = self.myQMenuBar.addMenu('&Tools')
        btn_drift = QtGui.QAction('Active DriftNet', self)
        btn_drift.setShortcut('Ctrl+Y')
        btn_drift.triggered.connect(self.show_driftnet)
        btn_drift.setIcon(QtGui.QIcon('icons/capture.png'))
        Menu_tools.addAction(btn_drift)

        # server Menu
        Menu_Server = self.myQMenuBar.addMenu('&Server')
        btn_phishing = QtGui.QAction('Phishing Manager',self)
        btn_winup = QtGui.QAction('Windows Update',self)
        btn_winup.setShortcut('Ctrl+N')
        btn_phishing.setShortcut('ctrl+Z')
        Menu_Server.addAction(btn_phishing)
        Menu_Server.addAction(btn_winup)

        #menu module
        Menu_module = self.myQMenuBar.addMenu('&Modules')
        btn_deauth = QtGui.QAction('Wi-Fi deauthentication', self)
        btn_probe = QtGui.QAction('Wi-Fi Probe Request',self)
        btn_dhcpStar = QtGui.QAction('DHCP Starvation',self)
        btn_arp = QtGui.QAction('ARP Poisoner ',self)
        btn_dns = QtGui.QAction('DNS Spoofer ',self)

        # Shortcut modules
        btn_deauth.setShortcut('Ctrl+W')
        btn_probe.setShortcut('Ctrl+K')
        btn_dhcpStar.setShortcut('Ctrl+H')
        btn_dns.setShortcut('ctrl+D')
        btn_arp.setShortcut('ctrl+Q')
        action_settings.setShortcut('Ctrl+X')

        #connect buttons
        btn_probe.triggered.connect(self.showProbe)
        btn_deauth.triggered.connect(self.showDauth)
        btn_dhcpStar.triggered.connect(self.show_dhcpDOS)
        btn_winup.triggered.connect(self.show_windows_update)
        btn_arp.triggered.connect(self.show_arp_posion)
        btn_dns.triggered.connect(self.show_dns_spoof)
        btn_phishing.triggered.connect(self.show_PhishingManager)
        action_settings.triggered.connect(self.show_settings)

        #icons modules
        btn_arp.setIcon(QtGui.QIcon('icons/arp_.png'))
        btn_winup.setIcon(QtGui.QIcon('icons/arp.png'))
        btn_dhcpStar.setIcon(QtGui.QIcon('icons/dhcp.png'))
        btn_probe.setIcon(QtGui.QIcon('icons/probe.png'))
        btn_deauth.setIcon(QtGui.QIcon('icons/deauth.png'))
        btn_dns.setIcon(QtGui.QIcon('icons/dns_spoof.png'))
        btn_phishing.setIcon(QtGui.QIcon('icons/page.png'))
        action_settings.setIcon(QtGui.QIcon('icons/setting.png'))

        # add modules menu
        Menu_module.addAction(btn_deauth)
        Menu_module.addAction(btn_probe)
        Menu_module.addAction(btn_dhcpStar)
        Menu_module.addAction(btn_arp)
        Menu_module.addAction(btn_dns)

        #menu extra
        Menu_extra= self.myQMenuBar.addMenu('&Help')
        Menu_update = QtGui.QAction('Check for Updates',self)
        Menu_about = QtGui.QAction('About WiFi-Pumpkin',self)
        Menu_issue = QtGui.QAction('Submit issue',self)
        Menu_donate = QtGui.QAction('Donate',self)
        Menu_about.setIcon(QtGui.QIcon('icons/about.png'))
        Menu_issue.setIcon(QtGui.QIcon('icons/report.png'))
        Menu_update.setIcon(QtGui.QIcon('icons/update.png'))
        Menu_donate.setIcon(QtGui.QIcon('icons/donate.png'))
        Menu_about.triggered.connect(self.about)
        Menu_issue.triggered.connect(self.issue)
        Menu_donate.triggered.connect(self.donate)
        Menu_update.triggered.connect(self.show_update)
        Menu_extra.addAction(Menu_donate)
        Menu_extra.addAction(Menu_issue)
        Menu_extra.addAction(Menu_update)
        Menu_extra.addAction(Menu_about)
        # create box default Form
        self.boxHome = QtGui.QVBoxLayout(self)
        self.boxHome.addWidget(self.myQMenuBar)

        # create Horizontal widgets
        hbox = QtGui.QHBoxLayout()
        self.hBoxbutton.addWidget(self.LeftTabBar)
        self.hBoxbutton.addWidget(self.progress)
        # add button start and stop
        hbox.addLayout(self.hBoxbutton)
        hbox.addWidget(self.Stack)
        self.boxHome.addLayout(hbox)
        self.boxHome.addWidget(self.StatusBar)
        self.LeftTabBar.setCurrentRow(self.index)
        self.setLayout(self.boxHome)



    def SetupUI(self):
        ''' configure all widget in home page '''
        self.StatusBar = QtGui.QStatusBar()
        self.StatusBar.setFixedHeight(23)
        self.connectedCount = QtGui.QLabel('')
        self.status_ap_runing = QtGui.QLabel('')
        self.connected_status = QtGui.QLabel('')
        self.set_status_label_AP(False)
        self.progress = ProgressBarWid(total=101)
        self.progress.setFixedHeight(13)
        self.progress.setFixedWidth(170)

        #self.progress.setFixedWidth(140)
        # add widgets in status bar
        self.StatusBar.addWidget(QtGui.QLabel('Connection:'))
        self.StatusBar.addWidget(self.connected_status)
        self.StatusBar.addWidget(QtGui.QLabel('Plugin:'))
        self.StatusBar.addWidget(self.status_plugin_proxy_name)
        self.StatusBar.addWidget(QtGui.QLabel("Status-AP:"))
        self.StatusBar.addWidget(self.status_ap_runing)

        self.StatusBar.addWidget(QtGui.QLabel(''),20)
        self.StatusBar.addWidget(QtGui.QLabel("Clients:"))
        self.connectedCount.setText("0")
        self.connectedCount.setStyleSheet("QLabel {  color : yellow; }")
        self.StatusBar.addWidget(self.connectedCount)


        self.EditGateway = QtGui.QLineEdit(self)
        self.EditGateway.setFixedWidth(120)
        self.EditGateway.setHidden(True)  # disable Gateway
        #edits
        self.set_initials_configsGUI()

        self.btn_start_attack = QtGui.QPushButton('Start', self)
        self.btn_start_attack.setIcon(QtGui.QIcon('icons/start.png'))
        self.btn_cancelar = QtGui.QPushButton('Stop', self)
        self.btn_cancelar.setIcon(QtGui.QIcon('icons/Stop.png'))
        self.btn_cancelar.clicked.connect(self.stop_access_point)
        self.btn_start_attack.clicked.connect(self.start_access_point)
        self.btn_cancelar.setEnabled(False)


        self.hBoxbutton =QtGui.QVBoxLayout()
        self.Formbuttons  = QtGui.QHBoxLayout()
        self.Formbuttons.addWidget(self.btn_start_attack)
        self.Formbuttons.addWidget(self.btn_cancelar)
        self.hBoxbutton.addLayout(self.Formbuttons)

    def show_arp_posion(self):
        ''' call GUI Arp Poison module '''
        if not self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            self.Farp_posion = GUIModules.frm_Arp_Poison(self.window_phishing)
            self.Farp_posion.setGeometry(0, 0, 450, 300)
            return self.Farp_posion.show()
            QtGui.QMessageBox.information(self,'ARP Poison Attack','this module not work with AP mode enabled. ')

    def show_update(self):
        ''' call GUI software Update '''
        self.FUpdate = self.UpdateSoftware
        self.FUpdate.show()

    def show_exportlogger(self):
        ''' call GUI Report Logger files '''
        self.SessionsAP= loads(str(self.FSettings.Settings.get_setting('accesspoint','sessions')))
        self.FrmLogger =  frm_ReportLogger(self.SessionsAP)
        self.FrmLogger.show()

    def show_settings(self):
        self.FSettings.show()

    def show_windows_update(self):
        ''' call GUI Windows Phishing Page module '''
        self.FWinUpdate = GUIModules.frm_update_attack()
        self.FWinUpdate.setGeometry(QtCore.QRect(100, 100, 300, 300))
        self.FWinUpdate.show()

    def show_dhcpDOS(self):
        ''' call GUI DHCP attack module '''
        self.Fstar = GUIModules.frm_dhcp_Attack()
        self.Fstar.setGeometry(QtCore.QRect(100, 100, 450, 200))
        self.Fstar.show()

    def showProbe(self):
        ''' call GUI Probe Request monitor module '''
        self.Fprobe = GUIModules.frm_PMonitor()
        self.Fprobe.show()

    def showDauth(self):
        ''' call GUI deauth module '''
        self.Fdeauth =GUIModules.frm_deauth()
        self.Fdeauth.setGeometry(QtCore.QRect(100, 100, 200, 200))
        self.Fdeauth.show()

    def show_dns_spoof(self):
        ''' call GUI DnsSpoof module '''
        if  self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if self.proxy.isChecked():
                return QtGui.QMessageBox.information(self,'DnsSpoof with AP','if you want to use the module'
                ' Dns Spoof Attack with AP started, you need to disable Proxy Server. You can change this in plugins tab'
                ' and only it necessary that the option "Enable Proxy Server"  be unmarked and '
                'restart the AP(Access Point).')
        self.Fdns = GUIModules.frm_DnsSpoof(self.window_phishing)
        self.Fdns.setGeometry(QtCore.QRect(100, 100, 450, 500))
        self.Fdns.show()

    def show_PhishingManager(self):
        ''' call GUI phishing attack  '''
        self.FPhishingManager = self.window_phishing
        self.FPhishingManager.txt_redirect.setText('0.0.0.0')
        self.FPhishingManager.show()

    def show_driftnet(self):
        ''' start tool driftnet in Thread '''
        if self.SettingsEnable['ProgCheck'][2]:
            if self.SettingsEnable['ProgCheck'][6]:
                if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
                    Thread_driftnet = ThreadPopen(['driftnet', '-i',
                    self.SettingsEnable['AP_iface'],'-d','./logs/Tools/Driftnet/',])
                    Thread_driftnet.setObjectName('Tool::Driftnet')
                    self.Apthreads['RogueAP'].append(Thread_driftnet)
                    return Thread_driftnet.start()
                return QtGui.QMessageBox.information(self,'Accesspoint is not running',
                'The access point is not configured, this option require AP is running...')
            return QtGui.QMessageBox.information(self,'xterm','xterm is not installed.')
        return QtGui.QMessageBox.information(self,'driftnet','driftnet is not found.')

    #TODO Home Widget Routine
    def check_status_ap_dashboard(self):
        ''' show/hide dashboard infor '''
        if self.statusap_action.isChecked():
            self.Home.APStatus.scroll.setHidden(False)
            return self.FSettings.Settings.set_setting('settings', 'show_dashboard_info', True)
        self.FSettings.Settings.set_setting('settings', 'show_dashboard_info', False)
        self.Home.APStatus.scroll.setHidden(True)

    def check_NetworkConnection(self):
        ''' update inferfaces '''
        self.btrn_find_Inet.setEnabled(False)
        interfaces = Refactor.get_interfaces()
        self.set_StatusConnected_Iface(False,'checking...',check=True)
        QtCore.QTimer.singleShot(3000, lambda: self.set_backgroud_Network(interfaces))

    def add_DHCP_Requests_clients(self,mac,user_info):
        ''' get HDCP request data and send for Tab monitor '''
        return self.StationMonitor.addRequests(mac,user_info,True)

    def add_data_into_QTableWidget(self,client):
        self.Home.DHCP.ClientTable.addNextWidget(client)

    def add_avaliableIterfaces(self,ifaces):
        for index,item in enumerate(ifaces):
            if search('wl', item):
                self.SessionConfig.Wireless.WLANCard.addItem(ifaces[index])
        return self.SessionConfig.Wireless.setEnabled(True)


    def set_dhcp_setings_ap(self,data):
        ''' get message dhcp configuration '''
        QtGui.QMessageBox.information(self,'settings DHCP',data)

    def set_index_leftMenu(self,i):
        ''' show content tab index TabMenuListWidget '''
        self.Stack.setCurrentIndex(i)

    def set_backgroud_Network(self,get_interfaces):
        ''' check interfaces on background '''
        if get_interfaces['activated'][0] != None:
            self.InternetShareWiFi = True
            self.btrn_find_Inet.setEnabled(True)
            return self.set_StatusConnected_Iface(True, get_interfaces['activated'][0])
        self.InternetShareWiFi = False
        self.btrn_find_Inet.setEnabled(True)
        return self.set_StatusConnected_Iface(False,'')

    def set_status_label_AP(self,bool):
        if bool:
            self.status_ap_runing.setText("[ON]")
            self.status_ap_runing.setStyleSheet("QLabel {  color : green; }")
        else:
            self.status_ap_runing.setText("[OFF]")
            self.status_ap_runing.setStyleSheet("QLabel {  color : #df1f1f; }")

    def set_proxy_statusbar(self,name,disabled=False):
        if not disabled:
            self.status_plugin_proxy_name.setText('[ {} ]'.format(name))
            self.status_plugin_proxy_name.setStyleSheet("QLabel { background-color: #996633; color : #000000; }")
        else:
            self.status_plugin_proxy_name.setText('[ Disabled ]')
            self.status_plugin_proxy_name.setStyleSheet("QLabel {  background-color: #808080; color : #000000; }")

    def set_StatusConnected_Iface(self,bool,txt='',check=False):
        if bool:
            self.connected_status.setText('[{}]'.format(txt))
            self.connected_status.setStyleSheet("QLabel {  background-color: #996633; color : #000000; }")
        elif bool == False and check == True:
            self.connected_status.setText('[{}]'.format(txt))
            self.connected_status.setStyleSheet("QLabel {  background-color: #808080; color : #000000; }")
        elif bool == False:
            self.connected_status.setText('[None]')
            self.connected_status.setStyleSheet("QLabel {  background-color: #808080; color : #000000; }")


    def set_initials_configsGUI(self):
        ''' settings edits default and check tools '''
        self.get_interfaces = Refactor.get_interfaces()
        if  self.get_interfaces['activated'][0]:
            return self.set_StatusConnected_Iface(True,self.get_interfaces['activated'][0])
        self.InternetShareWiFi = False
        self.set_StatusConnected_Iface(False,'')

    def get_Session_ID(self):
        ''' get key id for session AP '''
        session_id = Refactor.generateSessionID()
        while session_id in self.SessionsAP.keys():
            session_id = Refactor.generateSessionID()
        self.window_phishing.session = session_id
        return session_id

    def get_disable_proxy_status(self,status):
        ''' check if checkbox proxy-server is enable '''
        self.set_proxy_statusbar('', disabled=True)

    def get_Error_Injector_tab(self,data):
        ''' get error when ssslstrip or plugin args is not exist '''
        QtGui.QMessageBox.warning(self,'Error Module::Proxy',data)

    def get_status_new_commits(self,flag):
        ''' checks for commits in repository on Github '''
        if flag and self.UpdateSoftware.checkHasCommits:
            reply = QtGui.QMessageBox.question(self, 'Update WiFi-Pumpkin',
                'would you like to update commits from (github)??', QtGui.QMessageBox.Yes |
                                               QtGui.QMessageBox.No, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                self.UpdateSoftware.show()
        self.Timer.terminate()


    def get_error_hostapdServices(self,data):
        '''check error hostapd on mount AP '''
        self.stop_access_point()
        return QtGui.QMessageBox.warning(self,'[ERROR] Hostpad',
        'Failed to initiate Access Point, '
        'check output process hostapd.\n\nOutput::\n{}'.format(data))

    def get_soft_dependencies(self):
        ''' check if Hostapd, isc-dhcp-server is installed '''
        self.hostapd_path = self.FSettings.Settings.get_setting('accesspoint','hostapd_path')
        if not path.isfile(self.hostapd_path):
            return QtGui.QMessageBox.information(self,'Error Hostapd','hostapd is not installed')
        if self.FSettings.Settings.get_setting('accesspoint','dhcpd_server',format=bool):
            if not self.SettingsEnable['ProgCheck'][3]:
                return QtGui.QMessageBox.warning(self,'Error dhcpd','isc-dhcp-server (dhcpd) is not installed')
        return True

    def get_PumpkinProxy_output(self,data):
        ''' get std_ouput the thread Pumpkin-Proxy and add in DockArea '''
        if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            self.PumpkinProxyTAB.tableLogging.writeModeData(data)
            self.LogPumpkinproxy.info(data)

    def deleteObject(self,obj):
        ''' reclaim memory '''
        del obj

    def clean_all_loggers(self):
        ''' delete all logger file in logs/ '''
        content = Refactor.exportHtml()
        resp = QtGui.QMessageBox.question(self, 'About Delete Logger',
            'do you want to delete logs?',QtGui.QMessageBox.Yes |
                                          QtGui.QMessageBox.No, QtGui.QMessageBox.No)
        if resp == QtGui.QMessageBox.Yes:
            del_item_folder(['logs/Caplog/*','logs/ImagesCap/*'])
            for keyFile in content['Files']:
                with open(keyFile,'w') as f:
                    f.write(''),f.close()
            self.FSettings.Settings.set_setting('accesspoint','sessions',dumps({}))
            QtGui.QMessageBox.information(self,'Logger','All Looger::Output has been Removed...')
        self.deleteObject(content)
        self.deleteObject(resp)

    def configure_network_AP(self):
        ''' configure interface and dhcpd for mount Access Point '''
        self.SettingsEnable['PortRedirect'] = self.FSettings.Settings.get_setting('settings','redirect_port')
        print('[*] Enable forwarding in iptables...')
        Refactor.set_ip_forward(1)
        # clean iptables settings
        for line in self.SettingsAP['kill']: exec_bash(line)
        # set interface using ifconfig
        for line in self.SettingsAP['interface']: exec_bash(line)
        # check if dhcp option is enabled.
        if self.FSettings.Settings.get_setting('accesspoint','dhcp_server',format=bool):
            with open(C.DHCPCONF_PATH,'w') as dhcp:
                for line in self.SettingsAP['dhcp-server']:dhcp.write(line)
                dhcp.close()
                if not path.isdir('/etc/dhcp/'): mkdir('/etc/dhcp')
                move(C.DHCPCONF_PATH, '/etc/dhcp/')

    def start_access_point(self):
        ''' start Access Point and settings plugins  '''

        if self.wireless.Start() != None: return

        print('\n[*] Loading debugging mode')
        # create session ID to logging process
        self.currentSessionID = self.get_Session_ID()
        self.SessionsAP.update({self.currentSessionID : {'started': None,'stoped': None}})
        self.SessionsAP[self.currentSessionID]['started'] = asctime()
        print('[*] Current Session::ID [{}]'.format(self.currentSessionID))


        self.ImageSniffer.TableImage.clear()
        self.ImageSniffer.TableImage.setRowCount(0)

        # disable options when started AP
        self.btn_start_attack.setDisabled(True)
        self.SessionConfig.DHCP.setEnabled(False)
        self.SessionConfig.DNSSettings.setEnabled(False)

        self.proxy.setEnabled(False)
        self.mitmhandler.setEnabled(False)
        self.btn_cancelar.setEnabled(True)

        #clear clients on table info
        self.Home.DHCP.ClientTable.clearInfoClients()

        # start section time
        self.Home.APStatus.update_labels()
        self.Home.APStatus.start_timer()

        self.set_status_label_AP(True)

        self.updateSettingsAP()
        
        self.dhcpcontrol.Start()
        self.dnsserver.Start()
        self.proxy.Start()
        self.mitmhandler.Start()


        #TODO Twisted Reactor still problematik
        #     if not self.THReactor.isRunning():
        #         self.THReactor.start()

        self.Apthreads['RogueAP'].insert(0,self.wireless.ActiveReactor)
        self.Apthreads['RogueAP'].insert(1,self.dhcpcontrol.ActiveReactor)
        self.Apthreads['RogueAP'].insert(2,self.dnsserver.ActiveReactor)
        #self.Apthreads['RogueAP'].append(self.dhcpcontrol.ActiveService)
        self.Apthreads['RogueAP'].extend(self.proxy.ActiveReactor)
        self.Apthreads['RogueAP'].extend(self.mitmhandler.ActiveReactor)

        if self.InternetShareWiFi:
            print('[*] Sharing Internet Connections with NAT...')
        iptables = []
        # get all rules in settings->iptables
        for index in xrange(self.FSettings.ListRules.count()):
           iptables.append(str(self.FSettings.ListRules.item(index).text()))
        for rulesetfilter in iptables:
            if self.InternetShareWiFi: # disable share internet from network
                if '$inet' in rulesetfilter:
                    rulesetfilter = rulesetfilter.replace('$inet',str(self.wireless.Activated.interfacesLink['activated'][0]))
                if '$wlan' in rulesetfilter:
                    rulesetfilter = rulesetfilter.replace('$wlan',self.SettingsEnable['AP_iface'])
            if '$inet' in rulesetfilter or '$wlan' in rulesetfilter:
                continue
            popen(rulesetfilter)

        # start all Thread in sessions

        self.FSettings.Settings.set_setting('runningconfig', 'totalthread', len(self.Apthreads['RogueAP']))
        i=100/len(self.Apthreads['RogueAP'])

        for thread in self.Apthreads['RogueAP']:
            if thread is not None:
                self.progress.update_bar_simple(i)
                self.progress.setText("Starting {}".format(thread.objectName()))
                QtCore.QThread.sleep(1)
                thread.start()

        self.progress.setValue(100)
        self.progress.hideProcessbar()

        self.FSettings.Settings.set_setting('accesspoint','ssid',str(self.SessionConfig.Wireless.EditSSID.text()))
        self.FSettings.Settings.set_setting('accesspoint','channel',str(self.SessionConfig.Wireless.EditChannel.value()))

    def stop_access_point(self):
        ''' stop all thread :Access point attack and restore all settings  '''
        if self.Apthreads['RogueAP'] == []: return
        print('-------------------------------')
        self.proxy.Stop()
        self.mitmhandler.Stop()
        self.dnsserver.Stop()
        self.dhcpcontrol.Stop()
        self.wireless.Stop()

        self.SessionConfig.DHCP.setEnabled(True)
        self.SessionConfig.DNSSettings.setEnabled(True)
        self.proxy.setEnabled(True)
        self.mitmhandler.setEnabled(True)

        self.FSettings.Settings.set_setting('accesspoint','statusAP',False)
        #TODO Fix this
        #self.FSettings.Settings.set_setting('accesspoint','bssid',str(self.EditBSSID.text()))
        self.SessionsAP[self.currentSessionID]['stoped'] = asctime()
        self.FSettings.Settings.set_setting('accesspoint','sessions',dumps(self.SessionsAP))

        try:
            for thread in self.Apthreads['RogueAP']:
                thread.stop()
            self.FSettings.Settings.set_setting('runningconfig', 'totalthread', 0)
        except Exception: pass
        # remove iptables commands and stop dhcpd if pesist in process
        for kill in self.SettingsAP['kill']: exec_bash(kill)
        # stop time count

        self.Home.APStatus.stop_timer()

        set_monitor_mode(self.SettingsEnable['AP_iface']).setDisable()
        self.set_status_label_AP(False)
        self.progress.setValue(1)
        self.progress.change_color('')
        self.progress.setText('')
        self.connectedCount.setText('0')
        self.Apthreads['RogueAP'] = []
        self.APclients = {}
        self.btn_cancelar.setEnabled(False)
        self.btn_start_attack.setEnabled(True)
        self.progress.showProcessBar()

    def about(self):
        ''' open about GUI interface '''
        self.Fabout = frmAbout(author,emails,
        version,update,license,desc)
        self.Fabout.show()

    def issue(self):
        ''' open issue in github page the project '''
        url = QtCore.QUrl('https://github.com/P0cL4bs/WiFi-Pumpkin/issues/new')
        if not QtGui.QDesktopServices.openUrl(url):
            QtGui.QMessageBox.warning(self, 'Open Url', 'Could not open url: {}'.format(url))

    def donate(self):
        ''' open page donation the project '''
        self.Fabout = frmAbout(author,emails,version,update,license,desc)
        self.Fabout.tabwid.setCurrentIndex(4)
        self.Fabout.show()
