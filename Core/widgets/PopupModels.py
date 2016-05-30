from re import search
import Modules as GUIs
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.Utils import Refactor
"""
Description:
    This program is a Core for wifi-pumpkin.py. file which includes functionality
    for load plugins mitm attack and phishing module.

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

class PopUpPlugins(QWidget):
    ''' this module control all plugins to MITM attack'''
    def __init__(self,FSettings):
        QWidget.__init__(self)
        self.FSettings = FSettings
        self.layout = QVBoxLayout()
        self.layoutform = QFormLayout()
        self.GroupPlugins = QGroupBox()
        self.GroupPlugins.setTitle('::Plugins::')
        self.GroupPlugins.setLayout(self.layoutform)
        self.check_sslstrip = QCheckBox('::ssLstrip')
        self.check_netcreds = QCheckBox('::net-creds')
        self.check_dns2proy = QCheckBox('::dns2proxy')
        self.check_sergioProxy  = QCheckBox('::sergio-proxy')
        self.check_dns2proy.clicked.connect(self.checkBoxDns2proxy)
        self.check_sslstrip.clicked.connect(self.checkBoxSslstrip)
        self.check_netcreds.clicked.connect(self.checkBoxNecreds)
        self.check_sergioProxy.clicked.connect(self.checkBoxSergioProxy)
        self.layoutform.addRow(self.check_sslstrip)
        self.layoutform.addRow(self.check_netcreds)
        self.layoutform.addRow(self.check_dns2proy)
        self.layoutform.addRow(self.check_sergioProxy)
        self.layout.addWidget(self.GroupPlugins)
        self.setLayout(self.layout)
    # control checkbox plugins
    def checkBoxSslstrip(self):
        if not self.check_sslstrip.isChecked():
            if not self.check_sergioProxy.isChecked():
                self.unset_Rules('sslstrip')
            self.FSettings.Settings.set_setting('plugins','sslstrip_plugin',False)
        elif self.check_sslstrip.isChecked():
            if not self.check_sergioProxy.isChecked():
                self.set_sslStripRule()
            self.FSettings.Settings.set_setting('plugins','sslstrip_plugin',True)

    def checkBoxSergioProxy(self):
        if self.check_sergioProxy.isChecked():
            if not self.check_sslstrip.isChecked():
                self.set_sslStripRule()
            self.FSettings.Settings.set_setting('plugins','sergioproxy_plugin',True)
        elif not self.check_sergioProxy.isChecked():
            if not self.check_sslstrip.isChecked():
                self.unset_Rules('sslstrip')
            self.FSettings.Settings.set_setting('plugins','sergioproxy_plugin',False)

    def checkBoxDns2proxy(self):
        if not self.check_dns2proy.isChecked():
            self.unset_Rules('dns2proxy')
            self.FSettings.Settings.set_setting('plugins','dns2proxy_plugin',False)
        elif self.check_dns2proy.isChecked():
            self.set_Dns2proxyRule()
            self.FSettings.Settings.set_setting('plugins','dns2proxy_plugin',True)
    def checkBoxNecreds(self):
        if self.check_netcreds.isChecked():
            self.FSettings.Settings.set_setting('plugins','netcreds_plugin',True)
        else:
            self.FSettings.Settings.set_setting('plugins','netcreds_plugin',False)

    # set rules to sslstrip
    def set_sslStripRule(self):
        item = QListWidgetItem()
        item.setText('iptables -t nat -A PREROUTING -p '+
        'tcp --destination-port 80 -j REDIRECT --to-port '+self.FSettings.redirectport.text())
        item.setSizeHint(QSize(30,30))
        self.FSettings.ListRules.addItem(item)
    # set redirect port rules dns2proy
    def set_Dns2proxyRule(self):
        item = QListWidgetItem()
        item.setText('iptables -t nat -A PREROUTING -p '+
        'udp --destination-port 53 -j REDIRECT --to-port 53')
        item.setSizeHint(QSize(30,30))
        self.FSettings.ListRules.addItem(item)

    def unset_Rules(self,type):
        items = []
        for index in xrange(self.FSettings.ListRules.count()):
            items.append(str(self.FSettings.ListRules.item(index).text()))
        for i,j in enumerate(items):
            if type == 'sslstrip':
                if search(str('tcp --destination-port 80 -j REDIRECT --to-port '+
                    self.FSettings.redirectport.text()),j):
                    self.FSettings.ListRules.takeItem(i)
            elif type =='dns2proxy':
                if search('udp --destination-port 53 -j REDIRECT --to-port 53',j):
                    self.FSettings.ListRules.takeItem(i)


class PopUpServer(QWidget):
    ''' this module fast access to phishing-manager'''
    def __init__(self,FSettings):
        QWidget.__init__(self)
        self.FSettings  = FSettings
        self.Ftemplates = GUIs.frm_PhishingManager()
        self.layout     = QVBoxLayout()
        self.FormLayout = QFormLayout()
        self.GridForm   = QGridLayout()
        self.StatusLabel        = QLabel(self)
        self.GroupBox           = QGroupBox()
        self.GroupBox.setTitle('::Server-HTTP::')
        self.GroupBox.setLayout(self.FormLayout)
        self.btntemplates       = QPushButton('Phishing M.')
        self.btnStopServer      = QPushButton('Stop Server')
        self.btnRefresh         = QPushButton('ReFresh')
        self.txt_IP             = QLineEdit(self)
        self.ComboIface         = QComboBox(self)
        self.txt_IP.setVisible(False)
        self.StatusServer(False)
        #icons
        self.btntemplates.setIcon(QIcon('Icons/page.png'))
        self.btnStopServer.setIcon(QIcon('Icons/close.png'))
        self.btnRefresh.setIcon(QIcon('Icons/refresh.png'))

        #conects
        self.refrash_interface()
        self.btntemplates.clicked.connect(self.show_template_dialog)
        self.btnStopServer.clicked.connect(self.StopLocalServer)
        self.btnRefresh.clicked.connect(self.refrash_interface)
        self.connect(self.ComboIface, SIGNAL('currentIndexChanged(QString)'), self.discoveryIface)

        #layout
        self.GridForm.addWidget(self.ComboIface,0,1)
        self.GridForm.addWidget(self.btnRefresh,0,2)
        self.GridForm.addWidget(self.btntemplates,1,1)
        self.GridForm.addWidget(self.btnStopServer,1,2)
        self.FormLayout.addRow(self.GridForm)
        self.FormLayout.addRow('Status::',self.StatusLabel)
        self.layout.addWidget(self.GroupBox)
        self.setLayout(self.layout)


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
            if search('at',j) or search('wl',j):
                self.ComboIface.addItem(n[i])
                self.discoveryIface()

    def discoveryIface(self):
        iface = str(self.ComboIface.currentText())
        ip = Refactor.get_Ipaddr(iface)
        self.txt_IP.setText(ip)

    def show_template_dialog(self):
        self.connect(self.Ftemplates,SIGNAL('Activated ( QString ) '), self.emit_template)
        self.Ftemplates.txt_redirect.setText(self.txt_IP.text())
        self.Ftemplates.show()
