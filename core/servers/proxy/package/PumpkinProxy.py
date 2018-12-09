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
from core.widgets.docks.dock import DockableWidget
from plugins.analyzers import *
from plugins.external.scripts import *

if (ThreadPumpkinProxy().isMitmProxyInstalled()):
    from plugins.extension import *
from core.widgets.notifications import ServiceNotify

class PumpkinProxyDock(DockableWidget):
    ''' get all output and filter data from Pumpkin-Proxy plugin'''
    def __init__(self, parent=None,title="",info={}):
        super(PumpkinProxyDock, self).__init__(parent,title,info)
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
        self.THeaders  = OrderedDict([ ('Plugin',[]),('Output',[])])
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())
        self.maindockwidget.horizontalHeader().resizeSection(0,150)
        self.get_AllPluginName()
        self.setWidget(self.maindockwidget)

    def get_AllPluginName(self):
        ''' get all name plugins PumpkinProxy'''
        try:
            plugin_classes = plugin.PluginTemplate.__subclasses__()
            for p in plugin_classes:
                self.pluginsName.append(p().Name)
        except NameError:
            pass

    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets'''
        for name in self.pluginsName:
            if name in data:
                self.THeaders['Output'].append(data[len('[{}]'.format(name)):])
                self.THeaders['Plugin'].append('[{}]'.format(name))

        Headers = []
        self.maindockwidget.setRowCount(len(self.THeaders['Plugin']))
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QtGui.QTableWidgetItem(item)
                if key == 'Plugin':
                    item.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                self.maindockwidget.setItem(m, n, item)
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())
        self.maindockwidget.verticalHeader().setDefaultSectionSize(27)
        self.maindockwidget.scrollToBottom()

    def stopProcess(self):
        self.maindockwidget.setRowCount(0)
        self.maindockwidget.clearContents()
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())

class PumpkinMitmproxy(ProxyMode):
    ''' settings  Transparent Proxy '''
    Name = "Pumpkin Proxy"
    Author = "Pumpkin-Dev"
    Description = "Intercepting HTTP data, this proxy server that allows to intercept requests and response on the fly"
    Icon = "icons/pumpkinproxy.png"
    ModSettings = True
    Hidden = False
    ModType = "proxy"  # proxy or server
    _cmd_array = []
    sendError = QtCore.pyqtSignal(str)

    def __init__(self, parent,**kwargs):
        super(PumpkinMitmproxy,self).__init__(parent)
        self.mainLayout     = QtGui.QVBoxLayout()
        self.config         = SettingsINI(C.PUMPPROXY_INI)
        self.plugins        = []
        self.main_method    = parent
        self.bt_SettingsDict    = {}
        self.check_PluginDict   = {}
        self.search_all_ProxyPlugins()
        #scroll area
        self.scrollwidget = QtGui.QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QtGui.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)
        self.dockwidget = PumpkinProxyDock(None,title=self.Name)
        self.search[self.Name] = str('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080')

        # create for add dock logging
        self.tabcontrol = QtGui.QTabWidget()
        self.tab1 = QtGui.QWidget()
        self.tab2 = QtGui.QWidget()
        self.page_1 = QtGui.QVBoxLayout(self.tab1)
        self.page_2 = QtGui.QVBoxLayout(self.tab2)
        self.tableLogging  = dockPumpkinProxy()

        self.tabcontrol.addTab(self.tab1, 'Plugins')
        #self.tabcontrol.addTab(self.tab2, 'Logging')

        self.TabPlugins = QtGui.QTableWidget()
        self.TabPlugins.setColumnCount(3)
        self.TabPlugins.setRowCount(len(self.plugins))
        self.TabPlugins.resizeRowsToContents()
        self.TabPlugins.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.TabPlugins.horizontalHeader().setStretchLastSection(True)
        self.TabPlugins.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.TabPlugins.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.TabPlugins.verticalHeader().setVisible(False)
        self.TabPlugins.verticalHeader().setDefaultSectionSize(27)
        self.TabPlugins.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('Plugins',[]),('Settings',[]),('Description',[])])
        self.TabPlugins.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabPlugins.horizontalHeader().resizeSection(0,158)
        self.TabPlugins.horizontalHeader().resizeSection(1,80)

        # add on tab
        self.page_1.addWidget(self.TabPlugins)
        self.page_2.addWidget(self.tableLogging)

        # get all plugins and add into TabWidget
        Headers = []
        for plugin in self.plugins:
            if plugin.ConfigParser:
                self.bt_SettingsDict[plugin.Name] = QtGui.QPushButton('Settings')
                self.bt_SettingsDict[plugin.Name].clicked.connect(partial(self.setSettingsPlgins,plugin.Name))
            else:
                self.bt_SettingsDict[plugin.Name] = QtGui.QPushButton('None')
            self.check_PluginDict[plugin.Name] = QtGui.QCheckBox(plugin.Name)
            self.check_PluginDict[plugin.Name].setObjectName(plugin.Name)
            self.check_PluginDict[plugin.Name].clicked.connect(partial(self.setPluginOption,plugin.Name))
            self.THeaders['Plugins'].append(self.check_PluginDict[plugin.Name])
            self.THeaders['Settings'].append({'name': plugin.Name})
            self.THeaders['Description'].append(plugin.Description)
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                if type(item) == type(QtGui.QCheckBox()):
                    self.TabPlugins.setCellWidget(m,n,item)
                elif type(item) == type(dict()):
                    self.TabPlugins.setCellWidget(m,n,self.bt_SettingsDict[item['name']])
                else:
                    item = QtGui.QTableWidgetItem(item)
                    self.TabPlugins.setItem(m, n, item)
        self.TabPlugins.setHorizontalHeaderLabels(self.THeaders.keys())

        # check status all checkbox plugins
        for box in self.check_PluginDict.keys():
            self.check_PluginDict[box].setChecked(self.config.get_setting('plugins',box,format=bool))

        self.mainLayout.addWidget(self.tabcontrol)
        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.setLayout(self.layout)

    def setPluginOption(self, name,status):
        ''' get each plugins status'''
        # enable realtime disable and enable plugin
        if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            self.reactor.ThreadPumpkinProxy.m.disablePlugin(name, status)
        self.config.set_setting('plugins',name,status)

    def setSettingsPlgins(self,plugin):
        ''' open settings options for each plugins'''
        key = 'set_{}'.format(plugin)
        self.widget = PumpkinProxySettings(key,self.config.get_all_childname(key))
        self.widget.show()

    def search_all_ProxyPlugins(self):
        ''' load all plugins function '''
        try:
            plugin_classes = plugin.PluginTemplate.__subclasses__()
            for p in plugin_classes:
                self.plugins.append(p())
        except NameError: 
            infoLabel = ServiceNotify(C.PUMPKINPROXY_notify,title='Package Requirement')
            self.mainLayout.addWidget(infoLabel)

            
    def boot(self):
        self.reactor = ThreadPumpkinProxy(self.parent.currentSessionID)
        self.reactor.send.connect(self.LogOutput)
        self.reactor.setObjectName(self.Name)
        self.SetRules("PumpkinProxy")

    def LogOutput(self, data):
        if self.FSettings.Settings.get_setting('accesspoint', 'statusAP', format=bool):
            self.dockwidget.writeModeData(data)
            self.logger.info(data)

    def Serve(self,on=True):
        if on:
            self.tableLogging.clearContents()
            plugin_classes = plugin.PluginTemplate.__subclasses__()
            for p in plugin_classes:
                self.plugins.append(p())
        # pumpkinproxy not use reactor twistted
        #self.server.start()
    def onProxyEnabled(self):
        self.SetRules(self.Name)

