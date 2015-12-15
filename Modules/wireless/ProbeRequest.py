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
from re import search
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.config.Settings import frm_Settings
from Modules.utils import Refactor,set_monitor_mode,ThreadProbeScan


class frm_Probe(QMainWindow):
    def __init__(self, parent=None):
        super(frm_Probe, self).__init__(parent)
        self.form_widget = frm_PMonitor(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowIcon(QIcon('rsc/icon.ico'))

class frm_PMonitor(QWidget):
    def __init__(self, parent=None):
        super(frm_PMonitor, self).__init__(parent)
        self.Main       = QVBoxLayout()
        self.config     = frm_Settings()
        self.Requests   = []
        self.data       = {'Devices':[],'MacAddress': [], 'SSIDs':[]}
        self.interface  = str(self.config.xmlSettings("interface", "monitor_mode", None, False))
        self.loadtheme(self.config.XmlThemeSelected())
        self.setWindowTitle("Probe Request wifi Monitor")
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.setupGUI()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def setupGUI(self):
        self.form0          = QFormLayout()
        self.StatusBar      = QStatusBar()
        self.StatusProbe    = QLabel("")
        self.StatusBar.addWidget(QLabel("::Scannner::"))
        self.StartedProbe(False)
        self.StatusBar.setFixedHeight(15)
        self.tables = QTableWidget(5,3)
        self.tables.setRowCount(100)
        self.tables.setFixedHeight(300)
        self.tables.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tables.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tables.resizeColumnsToContents()
        self.tables.resizeRowsToContents()
        self.tables.horizontalHeader().resizeSection(0,120)
        self.tables.horizontalHeader().resizeSection(1,110)
        self.tables.horizontalHeader().resizeSection(2,130)
        self.tables.verticalHeader().setVisible(False)
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)

        self.btn_scan = QPushButton('Start')
        self.btn_stop = QPushButton('Stop')
        self.btn_refrash = QPushButton('Refrash')
        self.btn_refrash.clicked.connect(self.refrash_interface)
        self.btn_stop.clicked.connect(self.StopProbeResquest)
        self.btn_scan.clicked.connect(self.StartProbeResquest)
        self.btn_scan.setIcon(QIcon('rsc/network.png'))
        self.btn_stop.setIcon(QIcon('rsc/network_off.png'))
        self.btn_refrash.setIcon(QIcon('rsc/refresh.png'))
        self.get_placa = QComboBox(self)
        self.loadCard()

        self.Grid = QGridLayout()
        self.Grid.addWidget(QLabel('Network Adapter: '),0,0)
        self.Grid.addWidget(self.get_placa,0,1)
        self.Grid.addWidget(self.btn_refrash,0,2)
        self.Grid.addWidget(self.btn_scan,1,0)
        self.Grid.addWidget(self.btn_stop,1,1)
        self.form0.addRow(self.tables)
        self.form1 = QFormLayout()
        self.form1.addRow(self.StatusBar)
        self.Main.addLayout(self.form0)
        self.Main.addLayout(self.Grid)
        self.Main.addLayout(self.form1)

        self.setLayout(self.Main)

    def loadCard(self):
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search("wlan", j):
                self.get_placa.addItem(n[i])

    def StartedProbe(self,bool):
        if bool:
            self.StatusProbe.setText("[ON]")
            self.StatusProbe.setStyleSheet("QLabel {  color : green; }")
        else:
            self.StatusProbe.setText("[OFF]")
            self.StatusProbe.setStyleSheet("QLabel {  color : red; }")
        self.StatusBar.addWidget(self.StatusProbe)

    def refrash_interface(self):
        self.get_placa.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search('wlan', j):
                self.get_placa.addItem(n[i])

    def threadReceiveScan(self,info):
        if info != 'finished':
            if info not in self.Requests:
                data = info.split('|')
                Headers = []
                self.data['SSIDs'].append(data[1])
                self.data['MacAddress'].append(data[0])
                self.data['Devices'].append(data[2])
                for n, key in enumerate(reversed(self.data.keys())):
                    Headers.append(key)
                    for m, item in enumerate(self.data[key]):
                        item = QTableWidgetItem(item)
                        item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                        self.tables.setItem(m, n, item)
                Headers = []
                for key in reversed(self.data.keys()):
                    Headers.append(key)
                self.tables.setHorizontalHeaderLabels(Headers)
                self.Requests.append(info)
                return

    def StopProbeResquest(self):
        self.ThreadProbe.stop()
        self.StartedProbe(False)
        set_monitor_mode(self.get_placa.currentText()).setDisable()
    def StartProbeResquest(self):
        if self.get_placa.currentText() == '':
            return QMessageBox.information(self, 'Network Adapter', 'Network Adapter Not found try again.')
        set_monitor_mode(self.get_placa.currentText()).setEnable()
        self.ThreadProbe = ThreadProbeScan(str(self.get_placa.currentText()))
        self.connect(self.ThreadProbe,SIGNAL('Activated ( QString ) '), self.threadReceiveScan)
        self.ThreadProbe.setObjectName('::ThreadScanProbe')
        self.ThreadProbe.start()
        self.StartedProbe(True)