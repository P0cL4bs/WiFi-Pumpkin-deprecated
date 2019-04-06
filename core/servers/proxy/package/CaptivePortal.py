from collections import OrderedDict
from datetime import datetime
from functools import partial
from os import path,system
from subprocess import call
import core.utility.constants as C
from core.main import  QtGui,QtCore
from core.servers.proxy.package.ProxyMode import ProxyMode
from core.utility.collection import SettingsINI
from core.utils import Refactor, exec_bash
from core.widgets.customiseds import AutoGridLayout
from core.utility.threads import  (ProcessThread)
from core.widgets.pluginssettings import CaptivePortalSettings, CaptivePortalPreviewImage
from core.widgets.docks.dock import DockableWidget
from plugins.captivePortal import *
from core.servers.http_handler.ServerHTTP import ThreadCaptivePortalHTTPServer
from ast import literal_eval
from urllib2 import urlopen
from zipfile import ZipFile

class CaptivePortalDock(DockableWidget):
    ''' get all output and filter data from Pumpkin-Proxy plugin'''
    def __init__(self, parent=None,title="",info={}):
        super(CaptivePortalDock, self).__init__(parent,title,info)
        self.setObjectName(title)
        self.logger = info
        self.processThread = None
        self.maindockwidget = QtGui.QTableWidget()
        self.pluginsName = []
        self.maindockwidget.setColumnCount(2)
        self.maindockwidget.resizeRowsToContents()
        self.maindockwidget.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.maindockwidget.horizontalHeader().setStretchLastSection(True)
        self.maindockwidget.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.maindockwidget.verticalHeader().setVisible(False)
        self.maindockwidget.verticalHeader().setDefaultSectionSize(27)
        self.maindockwidget.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('CaptivePortal',[]),('Logger',[])])
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())
        self.maindockwidget.horizontalHeader().resizeSection(0,150)
        self.get_AllPluginName()
        self.setWidget(self.maindockwidget)

    def get_AllPluginName(self):
        ''' get all name plugins CaptivePortal-Proxy'''
        plugin_classes = plugin.CaptiveTemplatePlugin.__subclasses__()
        for p in plugin_classes:
            self.pluginsName.append(p().Name)

    def writeModeData(self,data, plugin):
        ''' get data output and add on QtableWidgets'''
        #for name in self.pluginsName:
        self.THeaders['CaptivePortal'].append(plugin)
        self.THeaders['Logger'].append(data)

        Headers = []
        self.maindockwidget.setRowCount(len(self.THeaders['CaptivePortal']))
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QtGui.QTableWidgetItem(item)
                item.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                self.maindockwidget.setItem(m, n, item)
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())
        self.maindockwidget.verticalHeader().setDefaultSectionSize(27)
        self.maindockwidget.scrollToBottom()

    def stopProcess(self):
        self.maindockwidget.setRowCount(0)
        self.maindockwidget.clearContents()
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())

class CaptivePortal(ProxyMode):
    ''' settings  Captive Portal Proxy '''
    Name = "Captive Portal"
    Author = "Pumpkin-Dev"
    Description = "Captive-Portal allow the Attacker block Internet access for users until they open the page login page where a password is required before being allowed to browse the web."
    Icon = "icons/captive_portal.png"
    ModSettings = True
    Hidden = False
    ModType = "proxy"  # proxy or server
    _cmd_array = []
    sendError = QtCore.pyqtSignal(str)

    def __init__(self, parent,**kwargs):
        super(CaptivePortal,self).__init__(parent)
        self.mainLayout     = QtGui.QVBoxLayout()
        self.config         = SettingsINI(C.CAPTIVEPORTAL_INI)
        self.plugins        = []
        self.plugin_activated = None
        self.main_method    = parent
        self.bt_SettingsDict    = {}
        self.check_PluginDict   = {}
        self.ClientsLogged      = {}
        self.btn_previewSettings = {}
        self.search_all_ProxyPlugins()
        #scroll area
        self.scrollwidget = QtGui.QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QtGui.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)
        self.dockwidget = CaptivePortalDock(None,title=self.Name)

        # create for add dock logging
        self.tabcontrol = QtGui.QTabWidget()
        self.tab1 = QtGui.QWidget()
        self.tab2 = QtGui.QWidget()
        self.page_1 = QtGui.QVBoxLayout(self.tab1)
        self.page_2 = QtGui.QVBoxLayout(self.tab2)

        self.tabcontrol.addTab(self.tab1, 'Plugins')
        self.tabcontrol.addTab(self.tab2, 'Manager')
        self.TabCtrlClients = QtGui.QTableWidget()
        self.TabCtrlClients.setColumnCount(3)
        #self.TabCtrlClients.setRowCount(len(self.plugins))
        self.TabCtrlClients.resizeRowsToContents()
        self.TabCtrlClients.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.TabCtrlClients.horizontalHeader().setStretchLastSection(True)
        self.TabCtrlClients.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.TabCtrlClients.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.TabCtrlClients.verticalHeader().setVisible(False)
        self.TabCtrlClients.verticalHeader().setDefaultSectionSize(27)
        self.TabCtrlClients.setSortingEnabled(True)
        self.THeadersCtrlClients  = OrderedDict([('IpAddress',[]),('MacAddress',[]),('Status Internet',[])])
        self.TabCtrlClients.setHorizontalHeaderLabels(self.THeadersCtrlClients.keys())



        self.mainLayout_settings    = QtGui.QVBoxLayout()
        #scroll area
        self.scrollwidget_settings = QtGui.QWidget()
        self.scrollwidget_settings.setLayout(self.mainLayout_settings)
        self.scroll_settings = QtGui.QScrollArea()
        self.scroll_settings.setWidgetResizable(True)
        self.scroll_settings.setWidget(self.scrollwidget_settings)

        
        # create widgets
        self.argsLabel  = QtGui.QLabel('')
        self.hBox       = QtGui.QHBoxLayout()
        self.btnEnable  = QtGui.QPushButton('Allow')
        self.btncancel  = QtGui.QPushButton('Deny')

        # size buttons
        self.btnEnable.setFixedWidth(100)
        self.btncancel.setFixedWidth(100)

        self.comboxBoxIPAddress  = QtGui.QComboBox()
        self.btncancel.setIcon(QtGui.QIcon('icons/cancel.png'))
        self.btnEnable.setIcon(QtGui.QIcon('icons/accept.png'))

        # group settings
        self.GroupSettings  = QtGui.QGroupBox()
        self.GroupSettings.setTitle('Manage clients access:')
        self.SettingsLayout = QtGui.QFormLayout()
        self.hBox.addWidget(self.comboxBoxIPAddress)
        self.hBox.addWidget(self.btnEnable)
        self.hBox.addWidget(self.btncancel)
        self.SettingsLayout.addRow(self.hBox)
        self.GroupSettings.setLayout(self.SettingsLayout)
        #self.GroupSettings.setFixedWidth(450)


        #group logger
        self.GroupLogger  = QtGui.QGroupBox()
        self.logger_portal = QtGui.QListWidget()
        self.GroupLogger.setTitle('Logger events:')
        self.LoggerLayout = QtGui.QVBoxLayout()
        self.LoggerLayout.addWidget(self.logger_portal)
        self.GroupLogger.setLayout(self.LoggerLayout)
        #self.GroupLogger.setFixedWidth(450)


        #connections
        # self.btnLoader.clicked.connect(self.SearchProxyPlugins)
        self.connect(self.comboxBoxIPAddress,QtCore.SIGNAL('currentIndexChanged(QString)'),self.checkStatusClient)
        self.btnEnable.clicked.connect(self.enableInternetConnection)
        self.btncancel.clicked.connect(self.disableInternetConnection)
        # self.btnbrownser.clicked.connect(self.get_filenameToInjection)
        # add widgets
        self.mainLayout_settings.addWidget(self.GroupSettings)
        self.mainLayout_settings.addWidget(self.GroupLogger)



        self.TabPlugins = QtGui.QTableWidget()
        self.TabPlugins.setColumnCount(5)
        self.TabPlugins.setRowCount(len(self.plugins))
        self.TabPlugins.resizeRowsToContents()
        self.TabPlugins.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.TabPlugins.horizontalHeader().setStretchLastSection(True)
        self.TabPlugins.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.TabPlugins.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.TabPlugins.verticalHeader().setVisible(False)
        self.TabPlugins.verticalHeader().setDefaultSectionSize(27)
        self.TabPlugins.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('Captive Name',[]),('Preview',[]),('Author',[]),('Settings',[]),('Description',[])])
        self.TabPlugins.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabPlugins.horizontalHeader().resizeSection(0,158)
        self.TabPlugins.horizontalHeader().resizeSection(1,80)

        # add on tab
        self.page_1.addWidget(self.TabPlugins)
        self.page_2.addWidget(self.scroll_settings)

        # get all plugins and add into TabWidget
        Headers = []
        for plugin in self.plugins:
            if plugin.ConfigParser:
                self.bt_SettingsDict[plugin.Name] = QtGui.QPushButton('Settings')
                self.bt_SettingsDict[plugin.Name].clicked.connect(partial(self.setSettingsPlgins,plugin.Name))
            else:
                self.bt_SettingsDict[plugin.Name] = QtGui.QPushButton('None')

            if (path.isfile(plugin.Preview)):
                self.btn_previewSettings[plugin.Name] = QtGui.QPushButton('Preview')
                self.btn_previewSettings[plugin.Name].setObjectName(plugin.Preview)
                self.btn_previewSettings[plugin.Name].clicked.connect(partial(self.showPreviewCaptivePortal,plugin.Name))
            else:
                self.btn_previewSettings[plugin.Name] = QtGui.QPushButton('Not found')

            self.check_PluginDict[plugin.Name] = QtGui.QRadioButton(plugin.Name)
            self.check_PluginDict[plugin.Name].setObjectName(plugin.Name)
            self.check_PluginDict[plugin.Name].clicked.connect(partial(self.setPluginOption,plugin.Name))
            self.THeaders['Captive Name'].append(self.check_PluginDict[plugin.Name])
            self.THeaders['Preview'].append(self.btn_previewSettings[plugin.Name])
            self.THeaders['Author'].append(plugin.Author)
            self.THeaders['Settings'].append({'name': plugin.Name})
            self.THeaders['Description'].append(plugin.Description)
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                if type(item) == type(QtGui.QRadioButton()):
                    self.TabPlugins.setCellWidget(m,n,item)
                elif type(item) == type(dict()):
                    self.TabPlugins.setCellWidget(m,n,self.bt_SettingsDict[item['name']])
                elif type(item) == type(QtGui.QPushButton()):
                    self.TabPlugins.setCellWidget(m,n,item)
                else:
                    item = QtGui.QTableWidgetItem(item)
                    self.TabPlugins.setItem(m, n, item)
        self.TabPlugins.setHorizontalHeaderLabels(self.THeaders.keys())

        # check status all checkbox plugins
        for box in self.check_PluginDict.keys():
            self.check_PluginDict[box].setChecked(self.config.get_setting('plugins',box,format=bool))

        self.btn_updateCaptive = QtGui.QPushButton("Update")
        self.btn_updateCaptive.setIcon(QtGui.QIcon('icons/updates_.png'))
        self.btn_updateCaptive.setFixedWidth(130)
        self.btn_updateCaptive.clicked.connect(self.disableBtnForUpdates)


        self.mainLayout.addWidget(self.tabcontrol)
        self.mainLayout.addWidget(self.btn_updateCaptive)
        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.setLayout(self.layout)


    def disableBtnForUpdates(self):
        ''' update captive portals from github '''
        self.btn_updateCaptive.setEnabled(False)
        self.btn_updateCaptive.setText('Downloading...')
        QtCore.QTimer.singleShot(3000, lambda: self.downloadCaptiveportals())

    def downloadCaptiveportals(self):
        ''' check interfaces on background '''
        try:
            data_file = urlopen(C.EXTRACAPTIVETHEMES)
            with open(C.CAPTIVETHEMESZIP,'wb') as output:
                output.write(data_file.read())
        except Exception as e:
            self.btn_updateCaptive.setEnabled(True)
            self.btn_updateCaptive.setText('Update')
            return QtGui.QMessageBox.information(self, 'Error: Download data ',str(e))

        zip_ref = ZipFile(C.CAPTIVETHEMESZIP, 'r')
        zip_ref.extractall(C.TEMPPATH)
        zip_ref.close()

        source_path_templates = C.CAPTIVEPATH_TMP_TEMPLATES
        source_path_plugins = C.CAPTIVEPATH_TMP_PLUGINS
        config_captive = SettingsINI(C.PATHCAPTIVEFINI)

        for plugin in config_captive.get_all_childname('plugins'):
            if (not plugin in self.config.get_all_childname('plugins')):

                system('cp -r {src} {dst}'.format(src=source_path_templates+plugin, 
                dst=C.CAPTIVE_PATH_TEMPLATES))
                self.config.set_setting('plugins', plugin, False)

                for subplugin in config_captive.get_all_childname('set_{}'.format(plugin)):
                    if subplugin != 'Default':
                        self.config.set_setting('set_{}'.format(plugin), subplugin, False)
                    else:
                        self.config.set_setting('set_{}'.format(plugin), subplugin, True)
        
                system('cp {src} {dst}'.format(src='{}{}.py'.format(source_path_plugins,plugin), 
                dst=C.CAPTIVE_PATH_PLUGINS))
        
        self.btn_updateCaptive.setEnabled(True)
        self.btn_updateCaptive.setText('Update')
        QtGui.QMessageBox.information(self,'Update Captive-Portals',
        "Already up-to-date. Please restart WiFi-Pumpkin to apply this update.")
        

    def enableInternetConnection(self):
        ipaddress = str(self.comboxBoxIPAddress.currentText())
        exec_bash('iptables -D FORWARD -s {ip} -j REJECT'.format(ip=ipaddress)) 
        exec_bash('iptables -I FORWARD -s {ip} -j ACCEPT'.format(ip=ipaddress))
        self.btnEnable.setEnabled(False)
        self.btncancel.setEnabled(True) 
        self.ClientsLogged[ipaddress]['Status'] = True
        self.logger_portal.addItem('Allow access the internet to {}'.format(ipaddress))
     
    def disableInternetConnection(self):
        ipaddress = str(self.comboxBoxIPAddress.currentText())
        exec_bash('iptables -D FORWARD -s {ip} -j ACCEPT'.format(ip=ipaddress)) 
        exec_bash('iptables -I FORWARD -s {ip} -j REJECT'.format(ip=ipaddress)) 
        self.btnEnable.setEnabled(True)
        self.btncancel.setEnabled(False)
        self.ClientsLogged[ipaddress]['Status'] = False
        self.logger_portal.addItem('Deny access the internet to {}'.format(ipaddress))


    def checkStatusClient(self):
        if (str(self.comboxBoxIPAddress.currentText()) != ''): 
            if (self.ClientsLogged[str(self.comboxBoxIPAddress.currentText())]['Status']):
                self.btnEnable.setEnabled(False)
                self.btncancel.setEnabled(True)
                return None
            self.btnEnable.setEnabled(True)
            self.btncancel.setEnabled(False)       

    def showPreviewCaptivePortal(self, plugin, status):
        self.preview_form = CaptivePortalPreviewImage(plugin, self.btn_previewSettings[plugin].objectName())
        self.preview_form.show()

    def search_all_ProxyPlugins(self):
        ''' load all plugins function '''
        plugin_classes = plugin.CaptiveTemplatePlugin.__subclasses__()
        for p in plugin_classes:
            self.plugins.append(p())

    def setSettingsPlgins(self,plugin):
        ''' open settings options for each plugins'''
        key = 'set_{}'.format(plugin)
        self.widget = CaptivePortalSettings(key,self.config.get_all_childname(key))
        self.widget.show()
            
    def getPluginActivated(self):
        for plugin in self.plugins:
            if (self.config.get_setting('plugins',plugin.Name,format=bool)):
                self.plugin_activated = plugin
        self.plugin_activated.initialize() # change language if exist
        return self.plugin_activated
    

    def shutdown(self):
        self.logger_portal.clear()
        self.comboxBoxIPAddress.clear()
        self.ClearRules()
        self.ClientsLogged = {}

    def boot(self):
        
        # self.reactor = ThreadCaptivePortalHTTPServer('0.0.0.0',80,plugin_activated,self.parent.currentSessionID)
        # self.reactor.requestCredentails.connect(self.LogOutput)
        # self.reactor.requestLogin.connect(self.allowAccessLogin)
        # self.reactor.setObjectName(self.Name)

        self.reactor= ProcessThread({'python': ["server.py",
        '-t',self.getPluginActivated().TemplatePath, '-r',self.parent.SessionConfig.DHCP.conf['router'],
        '-s',self.getPluginActivated().StaticPath]}, "plugins/captivePortal/")
        self.reactor._ProcssOutput.connect(self.LogOutput)
        self.reactor.setObjectName(self.Name)

        # settings iptables for add support captive portal 
        IFACE = self.parent.SessionConfig.Wireless.WLANCard.currentText()
        IP_ADDRESS = self.parent.SessionConfig.DHCP.conf['router']
        PORT= 80
        
        print('[*] Settings for captive portal:')
        print(" -> Allow FORWARD UDP DNS")
        self.search[self.Name+"_forward"] = str('iptables -A FORWARD -i {iface} -p tcp --dport 53 -j ACCEPT'.format(iface=IFACE))
        print(" -> Allow traffic to captive portal")
        self.search[self.Name+"_allow"] = str('iptables -A FORWARD -i {iface} -p tcp --dport {port} -d {ip} -j ACCEPT'.format(iface=IFACE, port=PORT, ip=IP_ADDRESS))
        print(" -> Block all other traffic in access point")
        self.search[self.Name+"_block"] = str('iptables -A FORWARD -i {iface} -j DROP '.format(iface=IFACE))
        print(" -> Redirecting HTTP traffic to captive portal")
        self.search[self.Name+"redirect"] = str('iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j DNAT --to-destination {ip}:{port}'.format(iface=IFACE,ip=IP_ADDRESS, port=PORT))
        

        self.SetRules(self.Name+"_forward")
        self.SetRules(self.Name+"_allow")
        self.SetRules(self.Name+"_block")
        self.SetRules(self.Name+"redirect")

        # print('[*] Settings for captive portal:')
        # print(" -> Allow FORWARD UDP DNS")
        # call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
        # print(" -> Allow traffic to captive portal")
        # call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", str(PORT),"-d", IP_ADDRESS, "-j" ,"ACCEPT"])
        # print(" -> Block all other traffic in access point")
        # call(["iptables", "-A", "FORWARD", "-i", IFACE, "-j" ,"DROP"])
        # print(" -> Redirecting HTTP traffic to captive portal")
        # call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IFACE, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", "{}:{}".format(IP_ADDRESS, PORT)])



    def addClientCtrlManager(self,IPADDRESS):
        ''' get data output and add on QtableWidgets'''
        #for name in self.pluginsName:
        clientsTabHome = self.parent.Home.DHCP.ClientTable.APclients
        self.ClientsLogged[IPADDRESS] = { 'MAC': 'unknow', 'Status': True} 
        for mac_address in clientsTabHome.keys():
            if (clientsTabHome[mac_address]['IP'] == IPADDRESS):
                self.ClientsLogged[IPADDRESS]['MAC'] = clientsTabHome[mac_address]['MAC']

        self.comboxBoxIPAddress.addItems([IPADDRESS])
        self.logger_portal.addItem('Authorized user: [ IP: {} MAC: {} ]'.format(IPADDRESS,
        self.ClientsLogged[IPADDRESS]['MAC']))

    def LogOutput(self, data):
        if self.FSettings.Settings.get_setting('accesspoint', 'statusAP', format=bool):
            self.dockwidget.writeModeData(data, self.plugin_activated.Name)
            self.logger.info(data)

            try:
                dict_data = literal_eval(data)
                self.addClientCtrlManager(dict_data.keys()[0])
            except Exception:
                pass

    def setPluginOption(self, name,status):
        ''' get each plugins status'''
        self.config.set_setting('plugins',name,status)
        for plugin in self.plugins:
            if (plugin.Name != name):
                self.config.set_setting('plugins',plugin.Name,False)



    def Serve(self,on=True):
        pass

    def onProxyEnabled(self):
        self.SetRules(self.Name)

