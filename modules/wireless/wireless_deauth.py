import threading
from os import popen,path,makedirs
from re import search
from core.packets.wireless import ThreadDeauth,ThreadScannerAP
from core.utility.extract import airdump_start,get_network_scan
from core.loaders.models.PackagesUI import *
threadloading = {'deauth':[],'mdk3':[]}

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for wireless deauth attack.

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

class frm_deauth(PumpkinModule):
    def __init__(self, parent=None):
        super(frm_deauth, self).__init__(parent)
        self.Main           = QtGui.QVBoxLayout()
        self.setWindowTitle("Wireless Deauthentication Attack")
        self.setWindowIcon(QtGui.QIcon('icons/icon.ico'))
        self.ApsCaptured    = {}
        self.data           = {'Bssid':[], 'Essid':[], 'Channel':[]}
        self.window_qt()

    def closeEvent(self, event):
        global threadloading
        if len(threadloading['deauth']) != 0 or len(threadloading['mdk3']) != 0:
            reply = QtGui.QMessageBox.question(self, 'About Exit',"Are you sure that you want to quit?",
            QtGui.QMessageBox.Yes | QtGui.QMessageBox.No, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                event.accept()
                for i in threadloading['deauth']:
                    i.terminate()
                    print("[*] Deuath Thread Terminate")
                for i in threadloading['mdk3']:
                    i.stop(),i.join()
                self.deleteLater()
                return
            event.ignore()

    def select_target(self):
        item = self.tables.selectedItems()
        if item != []:
            self.linetarget.setText(item[2].text())
            return
        self.linetarget.clear()

    def window_qt(self):
        # base form add all widgets
        self.mForm = QtGui.QFormLayout()
        # base widget this make Objected responsive
        self.widget = QtGui.QWidget()
        self.layout = QtGui.QVBoxLayout(self.widget)

        #status bar attack
        self.statusbar = QtGui.QStatusBar()
        system = QtGui.QLabel('Deauthentication::')
        self.statusbar.addWidget(system)
        self.Controlador = QtGui.QLabel('')
        self.AttackStatus(False)

        # create table for add info devices APs
        self.tables = QtGui.QTableWidget(5,3)
        self.tables.setRowCount(50)
        self.tables.setMinimumHeight(200)
        self.tables.setSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        self.tables.horizontalHeader().setStretchLastSection(True)
        self.tables.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.tables.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.tables.clicked.connect(self.select_target)
        self.tables.resizeColumnsToContents()
        self.tables.resizeRowsToContents()
        self.tables.horizontalHeader().resizeSection(1,115)
        self.tables.horizontalHeader().resizeSection(0,80)
        self.tables.horizontalHeader().resizeSection(2,130)
        self.tables.verticalHeader().setVisible(False)
        self.tables.setSortingEnabled(True)
        Headers = []
        for n, key in enumerate(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)
        self.tables.verticalHeader().setDefaultSectionSize(23)

        # create inputs and controles
        self.linetarget = QtGui.QLineEdit(self)
        self.input_client = QtGui.QLineEdit(self)
        self.checkbox_client = QtGui.QCheckBox(self)
        self.checkbox_client.setText('Set a custom client to deauthenticate')
        self.checkbox_client.clicked.connect(self.get_event_checkbox_client)
        self.input_client.setText("ff:ff:ff:ff:ff:ff")
        self.btn_enviar = QtGui.QPushButton("Send Attack", self)
        self.btn_enviar.clicked.connect(self.attack_deauth)
        self.btn_scan_start = QtGui.QPushButton("Start Scan", self)
        self.btn_scan_start.clicked.connect(self.SettingsScan)
        self.btn_stop = QtGui.QPushButton("Stop  Attack ", self)
        self.btn_stop.clicked.connect(self.kill_thread)
        self.btn_scan_stop = QtGui.QPushButton('Stop Scan',self)
        self.btn_scan_stop.clicked.connect(self.kill_scanAP)
        self.btn_enviar.setFixedWidth(170)
        self.btn_stop.setFixedWidth(170)
        self.btn_scan_stop.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.input_client.setEnabled(False)
        #icons
        self.btn_scan_start.setIcon(QtGui.QIcon("icons/network.png"))
        self.btn_scan_stop.setIcon(QtGui.QIcon('icons/network_off.png'))
        self.btn_enviar.setIcon(QtGui.QIcon("icons/start.png"))
        self.btn_stop.setIcon(QtGui.QIcon("icons/Stop.png"))

        self.get_placa = QtGui.QComboBox(self)
        # get all wireless card avaliable
        all = Refactor.get_interfaces()['all']
        for count,card in enumerate(all):
            if search("wl", card):
                self.get_placa.addItem(all[count])

        # group Network card select
        self.GroupBoxNetwork = QtGui.QGroupBox()
        self.layoutGroupNW = QtGui.QHBoxLayout()
        self.GroupBoxNetwork.setLayout(self.layoutGroupNW)
        self.GroupBoxNetwork.setTitle('Network Adapter:')
        self.layoutGroupNW.addWidget(self.get_placa)
        self.layoutGroupNW.addWidget(self.btn_scan_start)
        self.layoutGroupNW.addWidget(self.btn_scan_stop)

        # group settings card select
        self.GroupBoxSettings = QtGui.QGroupBox()
        self.layoutGroupST = QtGui.QVBoxLayout()
        self.GroupBoxSettings.setLayout(self.layoutGroupST)
        self.GroupBoxSettings.setTitle('Settings:')
        self.layoutGroupST.addWidget(QtGui.QLabel('Target:'))
        self.layoutGroupST.addWidget(self.linetarget)
        self.layoutGroupST.addWidget(QtGui.QLabel('Options:'))
        self.layoutGroupST.addWidget(self.checkbox_client)
        self.layoutGroupST.addWidget(self.input_client)

        self.form0  = QtGui.QVBoxLayout()
        self.form0.addWidget(self.tables)
        self.form0.addWidget(self.GroupBoxNetwork)
        self.form0.addWidget(self.GroupBoxSettings)
        self.mForm.addRow(self.btn_enviar, self.btn_stop)
        self.mForm.addRow(self.statusbar)

        self.layout.addLayout(self.form0)
        self.layout.addLayout(self.mForm)
        self.Main.addWidget(self.widget)
        self.setLayout(self.Main)

    def get_event_checkbox_client(self):
        if self.configure.Settings.get_setting('settings','deauth') == 'packets_mdk3':
            QtGui.QMessageBox.warning(self,'mdk3 Deauth',
            'mdk3 Deauth not have these options, you can set custom '
            'client deauth on Modules->Settings->Advanced tab (mdk3 args option) ')
            return self.checkbox_client.setCheckable(False)
        if self.checkbox_client.isChecked():
            self.input_client.setEnabled(True)
        else:
            self.input_client.setEnabled(False)

    def scan_diveces_airodump(self):
        dirpath = "logs/Caplog/Dump"
        if not path.isdir(dirpath): makedirs(dirpath)
        self.data = {'Bssid':[], 'Essid':[], 'Channel':[]}
        exit_air = airdump_start(self.interface)
        if exit_air == None:
            self.cap = get_network_scan()
            if self.cap != None:
                for i in self.cap:
                    i = i.split('||')
                    if Refactor.check_is_mac(i[2]):
                        Headers = []
                        self.data['Channel'].append(i[0])
                        self.data['Essid'].append(i[1])
                        self.data['Bssid'].append(i[2])
                        for n, key in enumerate(self.data.keys()):
                            Headers.append(key)
                            for m, item in enumerate(self.data[key]):
                                item = QtGui.QTableWidgetItem(item)
                                item.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                                self.tables.setItem(m, n, item)
                    self.cap =[]

    def kill_scanAP(self):
        if hasattr(self,'thread_airodump'):popen('killall airodump-ng')
        if hasattr(self,'threadScanAP'):self.threadScanAP.stop()
        self.btn_scan_stop.setEnabled(False)
        self.btn_scan_start.setEnabled(True)

    def kill_thread(self):
        global threadloading
        for i in threadloading['deauth']:i.stop()
        for i in threadloading['mdk3']:
            i.stop(),i.join()
        self.btn_enviar.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.AttackStatus(False)

    def monitorThreadScan(self,apData):
        apData = list(apData.split('|'))
        if not str(apData[0]) in self.ApsCaptured.keys():
            self.ApsCaptured[str(apData[0])] = apData
            if Refactor.check_is_mac(str(apData[0])):
               self.data['Channel'].append(self.ApsCaptured[str(apData[0])][1])
               self.data['Essid'].append(self.ApsCaptured[str(apData[0])][2])
               self.data['Bssid'].append(str(apData[0]))
               Headers = []
               for n, key in enumerate(self.data.keys()):
                   Headers.append(key)
                   for m, item in enumerate(self.data[key]):
                       item = QtGui.QTableWidgetItem(item)
                       item.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                       self.tables.setItem(m, n, item)

    def SettingsScan(self):
        self.ApsCaptured    = {}
        self.data = {'Bssid':[], 'Essid':[], 'Channel':[]}
        if self.get_placa.currentText() == "":
            QtGui.QMessageBox.information(self, "Network Adapter", 'Network Adapter is not found. Try again.')
        else:
            self.interface = str(set_monitor_mode(self.get_placa.currentText()).setEnable())
            self.btn_scan_stop.setEnabled(True)
            self.btn_scan_start.setEnabled(False)
            if self.interface != None:
                if self.configure.Settings.get_setting('settings','scan_scapy',format=bool):
                    self.threadScanAP = ThreadScannerAP(self.interface)
                    self.connect(self.threadScanAP,QtCore.SIGNAL('Activated ( QString ) '), self.monitorThreadScan)
                    self.threadScanAP.setObjectName('Thread Scanner AP::scapy')
                    self.threadScanAP.start()
                elif self.configure.Settings.get_setting('settings','scan_airodump',format=bool):
                    if path.isfile(popen('which airodump-ng').read().split("\n")[0]):
                        if path.isfile(popen('which xterm').read().split("\n")[0]):
                            self.thread_airodump = threading.Thread(target=self.scan_diveces_airodump)
                            self.thread_airodump.daemon = True
                            return self.thread_airodump.start()
                        QtGui.QMessageBox.warning(self, 'Error xterm', 'xterm is not installed')
                    QtGui.QMessageBox.information(self,'Error airodump','airodump-ng is not installed')
            set_monitor_mode(self.get_placa.currentText()).setDisable()


    def attack_deauth(self):
        global threadloading
        if hasattr(self,'threadScanAP'):
            if not self.threadScanAP.stopped:
                return QtGui.QMessageBox.warning(self,'scanner','you need to stop the scanner Access Point')
        if hasattr(self,'thread_airodump'):
            if self.thread_airodump.isAlive():
                return QtGui.QMessageBox.warning(self,'scanner','you need to stop the scanner Access Point')
        if self.linetarget.text() == '':
            return QtGui.QMessageBox.warning(self, 'Target Error', 'Please select a target to attack')
        # get args for thread attack
        self.btn_stop.setEnabled(True)
        self.btn_enviar.setEnabled(False)
        self.bssid = str(self.linetarget.text())
        self.args = str(self.configure.Settings.get_setting('settings','mdk3'))

        # set card mode monitor
        self.interface = str(set_monitor_mode(self.get_placa.currentText()).setEnable())
        if self.configure.Settings.get_setting('settings','scapy_deauth',format=bool):
            self.AttackStatus(True)
            self.threadDeauth = ThreadDeauth(self.bssid,str(self.input_client.text()),self.interface)
            threadloading['deauth'].append(self.threadDeauth)
            self.threadDeauth.setObjectName('Deauth scapy')
            return self.threadDeauth.start()
        elif self.configure.Settings.get_setting('settings','mdk3_deauth',format=bool):
            if  path.isfile(popen('which mdk3').read().split("\n")[0]):
                self.AttackStatus(True)
                self.mdk3_arguments = {'mdk3':[self.interface]}
                [self.mdk3_arguments['mdk3'].append(x) for x in self.args.split()]
                self.mdk3_arguments['mdk3'].append(self.bssid)
                self.processmdk = ProcessThread(self.mdk3_arguments)
                self.processmdk.setObjectName('Thread::mdk3')
                threadloading['mdk3'].append(self.processmdk)
                return self.processmdk.start()
            QtGui.QMessageBox.information(self,'Error mdk3','mkd3 not installed')
            set_monitor_mode(self.get_placa.currentText()).setDisable()

    def AttackStatus(self,bool):
        if bool:
            self.Controlador.setText('[ON]')
            self.Controlador.setStyleSheet("QLabel {  color : green; }")
        else:
            self.Controlador.setText('[OFF]')
            self.Controlador.setStyleSheet("QLabel {  color : red; }")
        self.statusbar.addWidget(self.Controlador)

    @QtCore.pyqtSlot(QtCore.QModelIndex)
    def list_clicked(self, index):
        itms = self.list.selectedIndexes()
        for i in itms:
            attack = str(i.data().toString()).split()
            for i in attack:
                if Refactor.check_is_mac(i.replace(' ', '')):
                    self.linetarget.setText(str(i))
            if self.linetarget.text() == '':
                QtGui.QMessageBox.information(self, 'MacAddress',
                'Please select a valid MAC Address as target.')
