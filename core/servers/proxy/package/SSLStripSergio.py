from core.config.globalimport import *
from collections import OrderedDict
from datetime import datetime
from functools import partial
from os import path

import core.utility.constants as C
from core.main import  QtGui,QtCore
from core.servers.proxy.package.ProxyMode import ProxyMode
from core.utility.collection import SettingsINI
from core.utility.threads import ThreadPopen
from core.utils import Refactor
from core.widgets.customiseds import AutoGridLayout
from core.widgets.docks.dockmonitor import (
    dockAreaAPI,dockUrlMonitor,dockCredsMonitor,dockPumpkinProxy,dockTCPproxy
)
from core.utility.threads import  (
    ProcessHostapd,Thread_sergioProxy,
    ThRunDhcp,Thread_sslstrip,ProcessThread,
    ThreadReactor,ThreadPopen,ThreadPumpkinProxy
)
from core.widgets.pluginssettings import PumpkinProxySettings
from plugins.analyzers import *
from plugins.external.scripts import *
from core.widgets.docks.dock import DockableWidget


class ProxySSLstripDock(DockableWidget):
    id = "SSLStrip"
    title = "SSLStrip Logger"
    def __init__(self,parent=0,title="",infor={}):
        super(ProxySSLstripDock,self).__init__(parent)
        self.setWindowTitle(self.title)
        self.maindockwidget = QtGui.QListWidget()
        self.setWidget(self.maindockwidget)


    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets '''
        item = QtGui.QListWidgetItem()
        item.setText(data)
        item.setSizeHint(QtCore.QSize(27,27))
        item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsEditable | QtCore.Qt.ItemIsSelectable)
        self.maindockwidget.insertItem(self.maindockwidget.count()+1,item)
        self.maindockwidget.scrollToBottom()

    def stopProcess(self):
        self.maindockwidget.clear()




class SergioProxySSLstrip(ProxyMode):
    Name = "SSLstrip+Sergio"
    Author = "Ben Schmidt and xtr4nge"
    Description = "Sergio proxy is an HTTP proxy that was written in Python for the Twisted framework."
    Icon = "icons/mac.png"
    ModSettings = True
    ModType = "proxy"  # proxy or server
    _cmd_array = []
    Hidden = False
    plugins = []
    _PluginsToLoader = {'plugins': None,'Content':''}

    def __init__(self, parent, **kwargs):

        super(SergioProxySSLstrip, self).__init__(parent)
        self.main_method = parent
        self.urlinjected= []
        self.FSettings  =SuperSettings.getInstance()
        self.mainLayout    = QtGui.QVBoxLayout()
        self.dockwidget = ProxySSLstripDock(None, title=self.Name)
        self.dockwidget.setWindowTitle(self.Name)
        self.search[self.Name] = str('iptables -t nat -A PREROUTING -p tcp'+
        ' --destination-port 80 -j REDIRECT --to-port '+self.FSettings.redirectport.text())
        #scroll area
        self.scrollwidget = QtGui.QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QtGui.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)

        # create widgets
        self.argsLabel  = QtGui.QLabel('')
        self.hBox       = QtGui.QHBoxLayout()
        self.hBoxargs   = QtGui.QHBoxLayout()
        self.btnLoader  = QtGui.QPushButton('Reload')
        self.btnEnable  = QtGui.QPushButton('Enable')
        self.btncancel  = QtGui.QPushButton('Cancel')
        self.btnbrownser= QtGui.QPushButton('Browser')

        # size buttons
        self.btnLoader.setFixedWidth(100)
        self.btnEnable.setFixedWidth(100)
        self.btncancel.setFixedWidth(100)
        self.btnbrownser.setFixedWidth(100)

        self.comboxBox  = QtGui.QComboBox()
        self.log_inject = QtGui.QListWidget()
        self.docScripts = QtGui.QTextEdit()
        self.argsScripts= QtGui.QLineEdit()
        self.btncancel.setIcon(QtGui.QIcon('icons/cancel.png'))
        self.btnLoader.setIcon(QtGui.QIcon('icons/search.png'))
        self.btnEnable.setIcon(QtGui.QIcon('icons/accept.png'))
        self.btnbrownser.setIcon(QtGui.QIcon("icons/open.png"))
        self.argsScripts.setEnabled(False)
        self.btnbrownser.setEnabled(False)

        # group settings
        self.GroupSettings  = QtGui.QGroupBox()
        self.GroupSettings.setTitle('settings:')
        self.SettingsLayout = QtGui.QFormLayout()
        self.hBox.addWidget(self.comboxBox)
        self.hBox.addWidget(self.btnLoader)
        self.hBox.addWidget(self.btnEnable)
        self.hBox.addWidget(self.btncancel)
        self.hBoxargs.addWidget(self.argsLabel)
        self.hBoxargs.addWidget(self.argsScripts)
        self.hBoxargs.addWidget(self.btnbrownser)
        self.SettingsLayout.addRow(self.hBox)
        self.SettingsLayout.addRow(self.hBoxargs)
        self.GroupSettings.setLayout(self.SettingsLayout)
        #self.GroupSettings.setFixedWidth(450)
        #group logger
        self.GroupLogger  = QtGui.QGroupBox()
        self.GroupLogger.setTitle('Logger Injection:')
        self.LoggerLayout = QtGui.QVBoxLayout()
        self.LoggerLayout.addWidget(self.log_inject)
        self.GroupLogger.setLayout(self.LoggerLayout)
        #self.GroupLogger.setFixedWidth(450)

        #group descriptions
        self.GroupDoc  = QtGui.QGroupBox()
        self.GroupDoc.setTitle('Description:')
        self.DocLayout = QtGui.QFormLayout()
        self.DocLayout.addRow(self.docScripts)
        self.GroupDoc.setLayout(self.DocLayout)
        self.GroupDoc.setFixedHeight(100)

        #connections
        self.SearchProxyPlugins()
        self.readDocScripts('html_injector')
        self.btnLoader.clicked.connect(self.SearchProxyPlugins)
        self.connect(self.comboxBox,QtCore.SIGNAL('currentIndexChanged(QString)'),self.readDocScripts)
        self.btnEnable.clicked.connect(self.setPluginsActivated)
        self.btncancel.clicked.connect(self.unsetPluginsConf)
        self.btnbrownser.clicked.connect(self.get_filenameToInjection)
        # add widgets
        self.mainLayout.addWidget(self.GroupSettings)
        self.mainLayout.addWidget(self.GroupDoc)
        self.mainLayout.addWidget(self.GroupLogger)
        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.setLayout(self.layout)
    @property
    def CMD_ARRAY(self):
        self._cmd_array=[]
    def get_filenameToInjection(self):
        ''' open file for injection plugin '''
        filename = QtGui.QFileDialog.getOpenFileName(None,
        'load File','','HTML (*.html);;js (*.js);;css (*.css)')
        if len(filename) > 0:
            self.argsScripts.setText(filename)
            QtGui.QMessageBox.information(None, 'Scripts Loaders', 'file has been loaded with success.')

    def setPluginsActivated(self):
        ''' check arguments for plugins '''
        item = str(self.comboxBox.currentText())
        if self.controlui.isChecked():
            if self.plugins[str(item)]._requiresArgs:
                if len(self.argsScripts.text()) != 0:
                    self._PluginsToLoader['plugins'] = item
                    self._PluginsToLoader['Content'] = str(self.argsScripts.text())
                else:
                    return self.sendError.emit('this module proxy requires {} args'.format(self.argsLabel.text()))
            else:
                self._PluginsToLoader['plugins'] = item
            self.btnEnable.setEnabled(False)
            self.ProcessReadLogger()
            return self.main_method.set_proxy_scripts(True)
        self.sendError.emit('plugins::Proxy is not enabled.'
        '\n\nthis module need a proxy server(sslstrip) to work,'
        '\nchoice the plugin options with sslstrip enabled.'.format(self.argsLabel.text()))

    def ProcessReadLogger(self):
        '''function for read log injection proxy '''
        if path.exists(C.LOG_SSLSTRIP):
            with open(C.LOG_SSLSTRIP,'w') as bufferlog:
                bufferlog.write(''), bufferlog.close()
            self.injectionThread = ThreadPopen(['tail','-f',C.LOG_SSLSTRIP])
            self.connect(self.injectionThread,QtCore.SIGNAL('Activated ( QString ) '), self.GetloggerInjection)
            self.injectionThread.setObjectName('Pump-Proxy::Capture')
            return self.injectionThread.start()
        QtGui.QMessageBox.warning(self,'error proxy logger','Pump-Proxy::capture is not found')

    def GetloggerInjection(self,data):
        ''' read load file and add in Qlistwidget '''
        if Refactor.getSize(C.LOG_SSLSTRIP) > 255790:
            with open(C.LOG_SSLSTRIP,'w') as bufferlog:
                bufferlog.write(''), bufferlog.close()
        if data not in self.urlinjected:
            self.log_inject.addItem(data)
            self.urlinjected.append(data)
        self.log_inject.scrollToBottom()

    def readDocScripts(self,item):
        ''' check type args for all plugins '''
        try:
            self.docScripts.setText(self.plugins[str(item)].__doc__)
            if self.plugins[str(item)]._requiresArgs:
                if 'FilePath' in self.plugins[str(item)]._argsname:
                    self.btnbrownser.setEnabled(True)
                else:
                    self.btnbrownser.setEnabled(False)
                self.argsScripts.setEnabled(True)
                self.argsLabel.setText(self.plugins[str(item)]._argsname)
            else:
                self.argsScripts.setEnabled(False)
                self.btnbrownser.setEnabled(False)
                self.argsLabel.setText('')
        except Exception:
            pass

    def unsetPluginsConf(self):
        ''' reset config for all plugins '''
        if hasattr(self,'injectionThread'): self.injectionThread.stop()
        self._PluginsToLoader = {'plugins': None,'args':''}
        self.btnEnable.setEnabled(True)
        self.main_method.set_proxy_scripts(False)
        self.argsScripts.clear()
        self.log_inject.clear()
        self.urlinjected = []

    def SearchProxyPlugins(self):
        ''' search all plugins in directory plugins/external/proxy'''
        self.comboxBox.clear()
        self.plugin_classes = Plugin.PluginProxy.__subclasses__()
        self.plugins = {}
        for p in self.plugin_classes:
            self.plugins[p._name] = p()
        self.comboxBox.addItems(self.plugins.keys())

    def CMD_ARRAY(self):
        self._cmd_array = [C.DNS2PROXY_EXEC, '-i', str(self.Wireless.WLANCard.currentText()), '-k',
                           self.parent.currentSessionID]

        return self._cmd_array

    def Serve(self, on=True):
        if on:
            self.plugin_classes = Plugin.PluginProxy.__subclasses__()
            self.plugins = {}
            for p in self.plugin_classes:
                self.plugins[p._name] = p()
            if not self.server.isRunning():
                self.server.start()
        else:
            pass #self.server.stop()
    def Initialize(self):
        self.unset_Rules(self.Name)
    def boot(self):
        self.reactor = Thread_sergioProxy(self.parent.SettingsEnable['PortRedirect'],
                                          self.plugins, self._PluginsToLoader,
                                          self.parent.currentSessionID)
        self.reactor.logging.connect(self.get_logger)
        self.reactor.setObjectName("SergioProxy")
        self.SetRules(self.Name)

    def get_logger(self, data ):
        self.dockwidget.writeModeData(data)

    def SafeLog(self):
        lines = []
        if self.log_inject.count()>0:
            with open('logs/AccessPoint/injectionPage.log','w') as injectionlog:
                for index in xrange(self.log_inject.count()):
                    lines.append(str(self.log_inject.item(index).text()))
                for log in lines: injectionlog.write(log+'\n')
                injectionlog.close()
    def onProxyEnabled(self):
        self.SetRules(self.Name)

