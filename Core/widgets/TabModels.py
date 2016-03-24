from Proxy import *
from os import path
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from datetime import datetime
from Core.Utils import Refactor,ThreadPopen
from Core.config.Settings import frm_Settings
from Plugins.sergio_proxy.sslstrip.ProxyPlugins import ProxyPlugins
"""
Description:
    This program is a Core for wifi-pumpkin.py. file which includes functionality
    for pumpkin-proxy,pumokin-monitor,pumpkin-settings tab.

Copyright:
    Copyright (C) 2015-2016 Marcos Nesster P0cl4bs Team
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

class PumpkinProxy(QVBoxLayout):
    ''' settings  Transparent Proxy '''
    sendError = pyqtSignal(str)
    _PluginsToLoader = {'Plugins': None,'Content':''}
    def __init__(self,popup,parent = None):
        super(PumpkinProxy, self).__init__(parent)
        self.popup      = popup
        self.urlinjected= []
        self.FSettings  = frm_Settings()
        self.Home       = QFormLayout()
        self.statusbar  = QStatusBar()
        self.lname      = QLabel('Proxy::scripts::')
        self.lstatus    = QLabel('')
        self.argsLabel  = QLabel('')
        self.hBox       = QHBoxLayout()
        self.hBoxargs   = QHBoxLayout()
        self.btnLoader  = QPushButton('Reload')
        self.btnEnable  = QPushButton('Enable')
        self.btncancel  = QPushButton('Cancel')
        self.btnbrownser= QPushButton('Browser')
        self.comboxBox  = QComboBox()
        self.log_inject = QListWidget()
        self.docScripts = QTextEdit()
        self.argsScripts= QLineEdit()
        self.btncancel.setIcon(QIcon('Icons/cancel.png'))
        self.btnLoader.setIcon(QIcon('Icons/search.png'))
        self.btnEnable.setIcon(QIcon('Icons/accept.png'))
        self.btnbrownser.setIcon(QIcon("Icons/open.png"))
        self.statusbar.addWidget(self.lname)
        self.statusbar.addWidget(self.lstatus)
        self.docScripts.setFixedHeight(40)
        self.statusInjection(False)
        self.argsScripts.setEnabled(False)
        self.btnbrownser.setEnabled(False)

        # group settings
        self.GroupSettings  = QGroupBox()
        self.GroupSettings.setTitle('Settings:')
        self.SettingsLayout = QFormLayout()
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
        #group logger
        self.GroupLogger  = QGroupBox()
        self.GroupLogger.setTitle('Logger Injection:')
        self.LoggerLayout = QFormLayout()
        self.LoggerLayout.addRow(self.log_inject)
        self.GroupLogger.setLayout(self.LoggerLayout)

        #group descriptions
        self.GroupDoc  = QGroupBox()
        self.GroupDoc.setTitle('Description:')
        self.DocLayout = QFormLayout()
        self.DocLayout.addRow(self.docScripts)
        self.GroupDoc.setLayout(self.DocLayout)

        #connections
        self.SearchProxyPlugins()
        self.readDocScripts('html_injector')
        self.btnLoader.clicked.connect(self.SearchProxyPlugins)
        self.connect(self.comboxBox,SIGNAL('currentIndexChanged(QString)'),self.readDocScripts)
        self.btnEnable.clicked.connect(self.setPluginsActivated)
        self.btncancel.clicked.connect(self.unsetPluginsConf)
        self.btnbrownser.clicked.connect(self.get_filenameToInjection)
        # add widgets
        self.Home.addRow(self.GroupSettings)
        self.Home.addRow(self.GroupDoc)
        self.Home.addRow(self.GroupLogger)
        self.Home.addRow(self.statusbar)
        self.addLayout(self.Home)

    def get_filenameToInjection(self):
        filename = QFileDialog.getOpenFileName(None,
        'load File','','HTML (*.html);;js (*.js);;css (*.css)')
        if len(filename) > 0:
            self.argsScripts.setText(filename)
            QMessageBox.information(None, 'Scripts Loaders', 'file has been loaded with success.')

    def setPluginsActivated(self):
        if self.popup.check_sslstrip.isChecked():
            item = str(self.comboxBox.currentText())
            if self.plugins[str(item)]._requiresArgs:
                if len(self.argsScripts.text()) != 0:
                    self._PluginsToLoader['Plugins'] = item
                    self._PluginsToLoader['Content'] = str(self.argsScripts.text())
                else:
                    return self.sendError.emit('this module proxy requires {} args'.format(self.argsLabel.text()))
            else:
                self._PluginsToLoader['Plugins'] = item
            self.btnEnable.setEnabled(False)
            self.ProcessReadLogger()
            return self.statusInjection(True)
        self.sendError.emit('sslstrip is not enabled.'.format(self.argsLabel.text()))

    def ProcessReadLogger(self):
        if path.exists('Logs/AccessPoint/injectionPage.log'):
            self.injectionThread = ThreadPopen(['tail','-f','Logs/AccessPoint/injectionPage.log'])
            self.connect(self.injectionThread,SIGNAL('Activated ( QString ) '), self.GetloggerInjection)
            self.injectionThread.setObjectName('Pump-Proxy::Capture')
            return self.injectionThread.start()
        QMessageBox.warning(self,'error proxy logger','Pump-Proxy::capture is not found')

    def GetloggerInjection(self,data):
        if data not in self.urlinjected:
            self.log_inject.addItem(data)
            self.urlinjected.append(data)
        self.log_inject.scrollToBottom()

    def statusInjection(self,server):
        if server:
            self.lstatus.setText('[ ON ]')
            self.lstatus.setStyleSheet('QLabel {  color : green; }')
        else:
            self.lstatus.setText('[ OFF ]')
            self.lstatus.setStyleSheet('QLabel {  color : red; }')

    def readDocScripts(self,item):
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
        if hasattr(self,'injectionThread'): self.injectionThread.stop()
        self._PluginsToLoader = {'Plugins': None,'args':''}
        self.btnEnable.setEnabled(True)
        self.statusInjection(False)
        self.argsScripts.clear()
        self.log_inject.clear()
        self.urlinjected = []

    def SearchProxyPlugins(self):
        self.comboxBox.clear()
        self.plugin_classes = Plugin.PluginProxy.__subclasses__()
        self.plugins = {}
        for p in self.plugin_classes:
            self.plugins[p._name] = p()
        self.comboxBox.addItems(self.plugins.keys())




class PumpkinMonitor(QVBoxLayout):
    ''' Monitor Access Point cleints connections'''
    def __init__(self, parent = None):
        super(PumpkinMonitor, self).__init__(parent)
        self.FSettings      = frm_Settings()
        self.Home           = QFormLayout()
        self.GroupMonitor   = QGroupBox()
        self.MonitorTreeView= QTreeView()
        self.MonitorTreeView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.MonitorTreeView.setFixedHeight(330)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Devices','Informations'])
        self.MonitorTreeView.setModel(self.model)
        self.MonitorTreeView.setUniformRowHeights(True)
        self.MonitorTreeView.setColumnWidth(0,130)

        self.GroupMonitor.setTitle('Pump-Monitor::')
        self.MonitorLayout = QFormLayout()
        self.MonitorLayout.addRow(self.MonitorTreeView)
        self.GroupMonitor.setLayout(self.MonitorLayout)
        self.Home.addRow(self.GroupMonitor)
        self.addLayout(self.Home)

    def addRequests(self,macddress,user,status):
        if status:
            ParentMaster = QStandardItem('Connected:: {} at {}'.format(macddress,
            datetime.now().strftime("%H:%M")))
            ParentMaster.setIcon(QIcon('Icons/connected.png'))
            ParentMaster.setSizeHint(QSize(30,30))
            info1 = QStandardItem('{}'.format(user['device']))
            info2 = QStandardItem('{}'.format(user['IP']))
            info3 = QStandardItem('{}'.format(datetime.now().strftime("%Y-%m-%d %H:%M")))
            ParentMaster.appendRow([QStandardItem('Device::'),info1])
            ParentMaster.appendRow([QStandardItem('IPAddr::'),info2])
            ParentMaster.appendRow([QStandardItem('Current date::'),info3])
            self.model.appendRow(ParentMaster)
            return self.MonitorTreeView.setFirstColumnSpanned(ParentMaster.row(),
            self.MonitorTreeView.rootIndex(), True)

        ParentMaster = QStandardItem('Disconnected:: {} at {}'.format(macddress,
        datetime.now().strftime("%H:%M")))
        ParentMaster.setIcon(QIcon('Icons/disconnected.png'))
        ParentMaster.setSizeHint(QSize(30,30))
        info1 = QStandardItem('{}'.format(user['device']))
        info2 = QStandardItem('{}'.format(user['IP']))
        info3 = QStandardItem('{}'.format(datetime.now().strftime("%Y-%m-%d %H:%M")))
        ParentMaster.appendRow([QStandardItem('Device::'),info1])
        ParentMaster.appendRow([QStandardItem('IPAddr::'),info2])
        ParentMaster.appendRow([QStandardItem('Current date::'),info3])
        self.model.appendRow(ParentMaster)
        self.MonitorTreeView.setFirstColumnSpanned(ParentMaster.row(),
        self.MonitorTreeView.rootIndex(), True)





class PumpkinSettings(QVBoxLayout):
    ''' settings DHCP options'''
    sendMensage = pyqtSignal(str)
    def __init__(self, parent = None):
        super(PumpkinSettings, self).__init__(parent)
        self.SettingsDHCP  = {}
        self.FSettings     = frm_Settings()
        self.mainLayout    = QFormLayout()
        self.GroupDHCP     = QGroupBox()
        self.layoutDHCP    = QFormLayout()
        self.layoutbuttons = QHBoxLayout()
        self.btnDefault    = QPushButton('default')
        self.btnSave       = QPushButton('save settings')
        self.btnSave.setIcon(QIcon('Icons/export.png'))
        self.btnDefault.setIcon(QIcon('Icons/settings.png'))
        self.leaseTime_def = QLineEdit(self.FSettings.xmlSettings('leasetimeDef', 'value',None))
        self.leaseTime_Max = QLineEdit(self.FSettings.xmlSettings('leasetimeMax', 'value',None))
        self.netmask       = QLineEdit(self.FSettings.xmlSettings('netmask', 'value',None))
        self.range_dhcp    = QLineEdit(self.FSettings.xmlSettings('range', 'value',None))
        self.route         = QLineEdit(self.FSettings.xmlSettings('router', 'value',None))
        self.subnet        = QLineEdit(self.FSettings.xmlSettings('subnet', 'value',None))
        self.broadcast     = QLineEdit(self.FSettings.xmlSettings('broadcast', 'value',None))
        self.GroupDHCP.setTitle('DHCP-Settings')
        self.GroupDHCP.setLayout(self.layoutDHCP)
        self.layoutDHCP.addRow('default-lease-time',self.leaseTime_def)
        self.layoutDHCP.addRow('max-lease-time',self.leaseTime_Max)
        self.layoutDHCP.addRow('subnet',self.subnet)
        self.layoutDHCP.addRow('router',self.route)
        self.layoutDHCP.addRow('netmask',self.netmask)
        self.layoutDHCP.addRow('broadcast-address',self.broadcast)
        self.layoutDHCP.addRow('range-dhcp',self.range_dhcp)
        # layout add
        self.layoutbuttons.addWidget(self.btnSave)
        self.layoutbuttons.addWidget(self.btnDefault)
        self.layoutDHCP.addRow(self.layoutbuttons)

        # connects
        self.btnDefault.clicked.connect(self.setdefaultSettings)
        self.btnSave.clicked.connect(self.savesettingsDHCP)
        self.mainLayout.addRow(self.GroupDHCP)
        self.addLayout(self.mainLayout)

    def setdefaultSettings(self):
        self.leaseTime_def.setText(self.FSettings.xmlSettings('D-leasetimeDef', 'value',None))
        self.leaseTime_Max.setText(self.FSettings.xmlSettings('D-leasetimeMax', 'value',None))
        self.netmask.setText(self.FSettings.xmlSettings('D-netmask', 'value',None))
        self.range_dhcp.setText(self.FSettings.xmlSettings('D-range', 'value',None))
        self.route.setText(self.FSettings.xmlSettings('D-router', 'value',None))
        self.subnet.setText(self.FSettings.xmlSettings('D-subnet', 'value',None))
        self.broadcast.setText(self.FSettings.xmlSettings('D-broadcast', 'value',None))

    def savesettingsDHCP(self):
        self.FSettings.xmlSettings('leasetimeDef', 'value',str(self.leaseTime_def.text()))
        self.FSettings.xmlSettings('leasetimeMax', 'value',str(self.leaseTime_Max.text()))
        self.FSettings.xmlSettings('netmask', 'value', str(self.netmask.text()))
        self.FSettings.xmlSettings('range', 'value',str(self.range_dhcp.text()))
        self.FSettings.xmlSettings('router', 'value',str(self.route.text()))
        self.FSettings.xmlSettings('subnet', 'value',str(self.subnet.text()))
        self.FSettings.xmlSettings('broadcast', 'value',str(self.broadcast.text()))
        self.btnSave.setEnabled(False)
        self.sendMensage.emit('settings DHCP saved with success...')
        self.btnSave.setEnabled(True)

    def getPumpkinSettings(self):
        self.SettingsDHCP['leasetimeDef'] = str(self.leaseTime_def.text())
        self.SettingsDHCP['leasetimeMax'] = str(self.leaseTime_Max.text())
        self.SettingsDHCP['subnet'] = str(self.subnet.text())
        self.SettingsDHCP['router'] = str(self.route.text())
        self.SettingsDHCP['netmask'] = str(self.netmask.text())
        self.SettingsDHCP['broadcast'] = str(self.broadcast.text())
        self.SettingsDHCP['range'] = str(self.range_dhcp.text())
        return self.SettingsDHCP