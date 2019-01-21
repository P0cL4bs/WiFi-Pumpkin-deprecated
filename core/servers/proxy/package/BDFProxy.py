from collections import OrderedDict
from configobj import ConfigObj,Section
from datetime import datetime
from functools import partial
from os import path

import core.utility.constants as C
import modules as GUI
from core.loaders.models.PackagesUI import *
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


class BDFProxy(ProxyMode):
    Name = "BDF Proxy"
    Author = "secretsquirrel"
    Description = 'Patch Binaries via MITM: BackdoorFactory + mitmProxy, bdfproxy-ng is a fork and review of the original BDFProxy..'
    ModSettings = True
    Hidden = True
    _cmd_array = []
    ModType = "proxy"  # proxy or server

    def __init__(self, parent, **kwargs):
        super(BDFProxy,self).__init__(parent)
        self.search[self.Name] = str('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080')
        self.parent =  parent
    @property
    def CMD_ARRAY(self):
        self._cmd_array=[C.BDFPROXY_EXEC,'-k',self.parent.currentSessionID]
        return self._cmd_array
    def Configure(self):
        self.ConfigWindow = BDFProxySettings()
        self.ConfigWindow.show()
    def onProxyEnabled(self):
        self.SetRules(self.Name)


class BDFProxySettings(PumpkinModule):
    def __init__(self,parent=None,FSettings=None):
        super(BDFProxySettings, self).__init__(parent,FSettings)
        self.setWindowTitle('DBFProxy-ng Plugin settings')
        self.setGeometry(0,0,480, 500)
        self.main       = QtGui.QVBoxLayout()
        self.THeaders   = {'Config':[],'Value':[] }
        self.userConfig = ConfigObj(str(self.configure.Settings.get_setting('plugins','bdfproxy_config')))
        self.userConfig.interpolation = False
        self.center()
        self.GUI()

    def addRowTableWidget(self, _key, _value):
        ''' add items into TableWidget '''
        Headers = []
        self.THeaders['Config'].append(_key)
        self.THeaders['Value'].append(_value)
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QtGui.QTableWidgetItem(item)
                item.setFlags(item.flags() | QtCore.Qt.ItemIsEditable)
                self.TabSettings.setItem(m, n, item)
        self.TabSettings.resizeColumnToContents(0)

    def getAllRowTablesWidget(self):
        ''' dump all settings from table '''
        model = self.TabSettings.model()
        data,datafilter,self.key = [],OrderedDict(),None
        for row in range(model.rowCount()):
            data.append([])
            for column in range(model.columnCount()):
                index = model.index(row, column)
                data[row].append(str(model.data(index).toString()))
        datafilter['ESP'] = {}
        datafilter['LinuxIntelx86'] = {}
        datafilter['LinuxIntelx64'] = {}
        datafilter['WindowsIntelx86'] = {}
        datafilter['WindowsIntelx64'] = {}
        datafilter['MachoIntelx86'] = {}
        datafilter['MachoIntelx64'] = {}
        for count,item in enumerate(data):
            if count < 5:
                if item[0] != '' or item[1] != '':
                    datafilter['ESP'][item[0]] = item[1]
            else:
                if item[0] != '' or item[1] != '':
                    if item[1] in datafilter.keys():
                        self.key = item[1]
                    else:
                        datafilter[self.key][item[0]] = item[1]
        return datafilter

    def saveConfigObject(self):
        self.checkConfigKeysBDFProxy(saveObjct=True)
        QtGui.QMessageBox.information(self,'BDFProxy-ng settings','All settings in {} has been saved '
        'with success.'.format(str(self.configure.Settings.get_setting('plugins','bdfproxy_config'))))
        self.close()

    def checkConfigKeysBDFProxy(self,saveObjct=False):
        ''' save all change into file.conf '''
        if saveObjct: changedData = self.getAllRowTablesWidget()
        for target in self.userConfig['targets'].keys():
            if target == 'ALL':
                for item in self.userConfig['targets']['ALL']:
                    if type(self.userConfig['targets']['ALL'][item]) == str:
                        if saveObjct:
                            self.userConfig['targets']['ALL'][item] = changedData['ESP'][item]
                        else:
                            self.addRowTableWidget(item,self.userConfig['targets']['ALL'][item])
                    elif type(self.userConfig['targets']['ALL'][item]) == Section:
                        if saveObjct:
                            self.userConfig['targets']['ALL'][item] = changedData[item]
                        else:
                            self.addRowTableWidget('-'*35+'>',item)
                            for key in self.userConfig['targets']['ALL'][item]:
                                self.addRowTableWidget(key,self.userConfig['targets']['ALL'][item][key])
        if saveObjct: self.userConfig.write()

    def GUI(self):
        self.TabSettings = QtGui.QTableWidget(50,2)
        self.btnSave     = QtGui.QPushButton('Save settings')
        self.GroupBox    = QtGui.QGroupBox(self)
        self.widget      = QtGui.QWidget()
        self.layoutGroup = QtGui.QVBoxLayout(self.widget)
        self.GroupBox.setLayout(self.layoutGroup)
        self.GroupBox.setTitle('Options')
        self.checkConfigKeysBDFProxy()
        self.btnSave.clicked.connect(self.saveConfigObject)
        self.TabSettings.resizeRowsToContents()
        self.TabSettings.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.TabSettings.horizontalHeader().setStretchLastSection(True)
        self.TabSettings.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        #self.TabSettings.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.TabSettings.verticalHeader().setVisible(False)
        self.TabSettings.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabSettings.verticalHeader().setDefaultSectionSize(23)

        self.layout = QtGui.QVBoxLayout(self.widget)
        self.layoutGroup.addWidget(self.TabSettings)
        self.layout.addWidget(self.GroupBox)
        self.layout.addWidget(self.btnSave)
        self.main.addWidget(self.widget)
        self.setLayout(self.main)


