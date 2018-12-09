from subprocess import Popen
from core.utils import Refactor
from core.main import Initialize,QtGui
from core.utility.settings import frm_Settings
import core.utility.constants as C
from core.widgets.notifications import ServiceNotify
"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    for exclude network manager card.

Copyright:
    Copyright (C) 2015-2017 Marcos Nesster P0cl4bs Team
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

class UI_NetworkManager(QtGui.QWidget):
    def __init__(self, app,parent = None):
        super(UI_NetworkManager, self).__init__(parent)
        self.label = QtGui.QLabel()
        self.app   = app
        self.Main  = QtGui.QVBoxLayout()
        self.config = frm_Settings.instances[0]
        self.setGeometry(0, 0, 300, 120)
        self.setWindowTitle('Checking Connection')
        self.loadtheme(self.config.get_theme_qss())
        self.center()
        self.UI()

    def closeEvent(self, event):
        if self.check_no_internet.isChecked:
            self.app.UI.InternetShareWiFi = False # show window without internet connection
        self.app.center()
        self.app.show()
        print('WiFi-Pumpkin Running!')

    def loadtheme(self,theme):
        sshFile=('core/%s.qss'%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QtGui.QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def statusInetrnet(self,bool):
        if bool:
            self.statusLabel.setText("[ON]")
            self.statusLabel.setStyleSheet("QLabel {  color : green; }")
        else:
            self.statusLabel.setText("[OFF]")
            self.statusLabel.setStyleSheet("QLabel {  color : red; }")

    def getstatus_checkbox(self):
        if self.check_no_internet.isChecked():
            return self.btn_start.setEnabled(True)
        self.btn_start.setEnabled(False)

    def get_interfaceConnected(self):
        self.networkManager = CLI_NetworkManager()
        if self.networkManager.isWiFiConnected():
            self.cb_ifaces.addItem(self.networkManager.getInterfaceDefault())
            self.statusInetrnet(True)
            self.btn_start.setEnabled(True)
            self.check_no_internet.setEnabled(False)

    def startGUI(self):
        self.btn_start.setEnabled(False)
        self.close()

    def UI(self):
        self.widget     = QtGui.QWidget()
        self.statusBar  = QtGui.QStatusBar()
        self.layout     = QtGui.QVBoxLayout(self.widget)
        self.statusLabel = QtGui.QLabel()
        self.statusInetrnet(False)
        self.statusBar.setFixedHeight(20)
        self.statusBar.addWidget(QtGui.QLabel('Status Connection::'))
        self.statusBar.addWidget(self.statusLabel)

        self.groupBoxIface = QtGui.QGroupBox()
        self.components  = QtGui.QHBoxLayout()
        self.compostart  = QtGui.QHBoxLayout()
        self.checkboxlayout = QtGui.QFormLayout()
        self.btn_refrash = QtGui.QPushButton('Refresh')
        self.btn_start   = QtGui.QPushButton('Start GUI..')
        self.cb_ifaces   = QtGui.QComboBox()
        self.check_no_internet = QtGui.QCheckBox('Start without connection.')

        self.check_no_internet.clicked.connect(self.getstatus_checkbox)
        self.btn_refrash.clicked.connect(self.get_interfaceConnected)
        self.btn_start.clicked.connect(self.startGUI)
        self.groupBoxIface.setTitle('Interface/Wireless')
        self.btn_refrash.setIcon(QtGui.QIcon('icons/refresh.png'))
        self.btn_start.setIcon(QtGui.QIcon('icons/start.png'))
        self.btn_start.setEnabled(False)
        self.compostart.addStretch(1)
        self.compostart.addWidget(self.btn_start)
        self.groupBoxIface.setLayout(self.components)
        self.components.addWidget(self.cb_ifaces)
        self.components.addWidget(self.btn_refrash)
        self.checkboxlayout.addWidget(self.check_no_internet)

        self.infor = ServiceNotify('Click the "Refresh" for try detect your connection.',
        title='Attention',link=None,timeout=30000)
        self.layout.addWidget(self.infor)
        self.layout.addWidget(self.groupBoxIface)
        self.layout.addLayout(self.checkboxlayout)
        self.layout.addLayout(self.compostart)
        self.layout.addWidget(self.statusBar)
        self.Main.addWidget(self.widget)
        self.setLayout(self.Main)


class CLI_NetworkManager(object):
    ''' exclude USB card on startup 1.0'''
    def __init__(self,parent = None):
        super(CLI_NetworkManager, self).__init__()
        self.interfaces = Refactor.get_interfaces()
        self.mn_path = C.NETWORKMANAGER
        self.ifaceAvaliable = []
        self.flag = 0

    def isWiFiConnected(self):
        ''' check if interface default is type wireless '''
        if self.interfaces['activated'][1] == 'wireless':
            return True
        return False

    def getInterfaceDefault(self):
        return self.interfaces['activated'][0]

    def remove_settingsNM(self):
        ''' remove all wireless from Network-Manager.conf '''
        if self.get_ifacesAllWireless():
            for interface in self.ifaceAvaliable:
                Refactor.settingsNetworkManager(interface,Remove=True)

    def get_ifacesAllWireless(self):
        ''' get only wireless interface '''
        if self.isWiFiConnected():
            for iface in self.interfaces['all']:
                if iface[:2] in ['wl', 'wi', 'ra', 'at']:
                    if iface != self.interfaces['activated'][0]:
                        self.ifaceAvaliable.append(iface)
            return True
        return False

    def check_interfaceinNetWorkManager(self,interface):
        ''' check if interface is already in file config'''
        mac = Refactor.get_interface_mac(interface)
        if mac != None:
            if mac in open(self.mn_path,'r').read(): return True
            if interface in open(self.mn_path,'r').read(): return True
        return False

    def run(self):
        if self.get_ifacesAllWireless():
            if self.ifaceAvaliable != []:
                for interface in self.ifaceAvaliable:
                    if not self.check_interfaceinNetWorkManager(interface):
                        Refactor.settingsNetworkManager(interface)
                        self.flag = 1
            if self.flag:
                Refactor.kill_procInterfaceBusy()
                Popen(['service', 'network-manager', 'restart'])
                return True
        return False




