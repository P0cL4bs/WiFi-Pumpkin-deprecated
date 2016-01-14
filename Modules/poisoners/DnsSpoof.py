from os import chdir,getcwd,devnull
import threading
from multiprocessing import Process,Manager
from socket import gaierror
from re import search
from socket import gethostbyname
from Core.loaders.Stealth.PackagesUI import *
from Modules.spreads.UpdateFake import frm_update_attack
threadloading = {'template':[],'dnsspoof':[],'arps':[]}

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for Dns spoof Attack.

Copyright:
    Copyright (C) 2015 Marcos Nesster P0cl4bs Team
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

class frm_DnsSpoof(PumpkinModule):
    def __init__(self, parent=None):
        super(frm_DnsSpoof, self).__init__(parent)
        self.setWindowTitle('Dns Spoof Attack')
        self.Main       = QVBoxLayout()
        self.owd        = getcwd()
        self.loadtheme(self.configure.XmlThemeSelected())
        self.data       = {'IPaddress':[], 'Hostname':[], 'MacAddress':[]}
        self.ThreadDirc = {'dns_spoof':[]}
        global threadloading
        self.GUI()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About Exit Dns spoof',
            'Are you sure to close Dns spoof?', QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            if len(self.ThreadDirc['dns_spoof']) != 0:
                for i in self.ThreadDirc['dns_spoof']:i.stop()
                for i in threadloading['template']:
                    i.stop(),i.join()
                    threadloading['template'] = []
                if self.configure.xmlSettings('statusAP','value',None,False) == 'False':
                    Refactor.set_ip_forward(0)
            self.deleteLater()
            return
        event.ignore()


    def GUI(self):
        self.form           = QFormLayout()
        self.layoutform     = QFormLayout()
        self.movie          = QMovie('rsc/loading2.gif', QByteArray(), self)
        size                = self.movie.scaledSize()
        self.movie_screen   = QLabel()
        self.setGeometry(200, 200, size.width(), size.height())
        self.movie_screen.setFixedHeight(200)
        self.movie_screen.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.movie_screen.setAlignment(Qt.AlignCenter)
        self.movie.setCacheMode(QMovie.CacheAll)
        self.movie.setSpeed(100)
        self.movie_screen.setMovie(self.movie)
        self.movie_screen.setDisabled(False)

        self.movie.start()
        self.tables = QTableWidget(5,3)
        self.tables.setRowCount(100)
        self.tables.setFixedHeight(200)
        self.tables.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tables.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tables.clicked.connect(self.list_clicked_scan)
        self.tables.resizeColumnsToContents()
        self.tables.resizeRowsToContents()
        self.tables.horizontalHeader().resizeSection(1,120)
        self.tables.horizontalHeader().resizeSection(0,145)
        self.tables.horizontalHeader().resizeSection(2,158)
        self.tables.verticalHeader().setVisible(False)
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)

        self.ip_range = QLineEdit(self)
        self.txt_gateway = QLineEdit(self)
        self.txt_redirect = QLineEdit(self)
        self.txt_target = QLineEdit(self)
        self.ComboIface = QComboBox(self)
        self.connect(self.ComboIface, SIGNAL("currentIndexChanged(QString)"), self.discoveryIface)

        self.layoutform.addRow('Target:',self.txt_target)
        self.layoutform.addRow('gateway:',self.txt_gateway)
        self.layoutform.addRow('Redirect IP:',self.txt_redirect)
        self.layoutform.addRow('Range Scan:',self.ip_range)
        self.layoutform.addRow('Interface:',self.ComboIface)
        self.myListDns = QListWidget(self)
        self.SettingsGUI()

        self.myListDns.setMinimumWidth(self.myListDns.sizeHintForColumn(100))
        self.myListDns.setContextMenuPolicy(Qt.CustomContextMenu)
        self.myListDns.connect(self.myListDns,
        SIGNAL('customContextMenuRequested(QPoint)' ),
        self.listItemclicked)

        self.txt_status_scan = QLabel('')
        self.txt_statusarp = QLabel('')
        self.txt_status_phishing = QLabel('')

        self.StatusMonitor(False,'stas_scan')
        self.StatusMonitor(False,'dns_spoof')
        self.StatusMonitor(False,'stas_phishing')
        scan_range = self.configure.xmlSettings('scan','rangeIP',None,False)
        self.ip_range.setText(scan_range)

        # button conf
        self.btn_start_scanner = QPushButton('Scan')
        self.btn_stop_scanner = QPushButton('Stop')
        self.btn_Attack_Posion = QPushButton('Start Attack')
        self.btn_Stop_Posion = QPushButton('Stop Attack')
        self.btn_server = QPushButton('Phishing M.')
        self.btn_windows_update = QPushButton('Fake Update')
        self.btn_server.setFixedHeight(22)
        self.btn_stop_scanner.setFixedWidth(100)
        self.btn_start_scanner.setFixedWidth(100)
        self.btn_start_scanner.setFixedHeight(22)
        self.btn_stop_scanner.setFixedHeight(22)
        self.btn_windows_update.setFixedHeight(22)
        self.btn_server.setIcon(QIcon('rsc/page.png'))


        # connet buttons
        self.btn_start_scanner.clicked.connect(self.Start_scan)
        self.btn_stop_scanner.clicked.connect(self.Stop_scan)
        self.btn_Attack_Posion.clicked.connect(self.Start_Attack)
        self.btn_Stop_Posion.clicked.connect(self.kill_attack)
        self.btn_server.clicked.connect(self.show_template_dialog)
        self.btn_windows_update.clicked.connect(self.show_frm_fake)

        #icons
        self.btn_start_scanner.setIcon(QIcon('rsc/network.png'))
        self.btn_Attack_Posion.setIcon(QIcon('rsc/start.png'))
        self.btn_Stop_Posion.setIcon(QIcon('rsc/Stop.png'))
        self.btn_stop_scanner.setIcon(QIcon('rsc/network_off.png'))
        self.btn_windows_update.setIcon(QIcon('rsc/winUp.png'))

        # grid status modules
        self.grid0 = QGridLayout()
        self.grid0.minimumSize()
        self.grid0.addWidget(QLabel('DnsSpoof:'),0,2)
        self.grid0.addWidget(QLabel('Phishing:'),0,4)
        self.grid0.addWidget(QLabel('Scanner:'),0,0)
        self.grid0.addWidget(self.txt_status_scan,0,1)
        self.grid0.addWidget(self.txt_statusarp,0,3)
        self.grid0.addWidget(self.txt_status_phishing,0,5)

        # grid options
        self.grid1 = QGridLayout()
        self.grid1.addWidget(self.btn_start_scanner,0,0)
        self.grid1.addWidget(self.btn_stop_scanner,0,1)
        self.grid1.addWidget(self.btn_server,0,2)
        self.grid1.addWidget(self.btn_windows_update, 0,3)

        #btn start and stop
        self.grid2 = QGridLayout()
        self.grid2.addWidget(self.btn_Attack_Posion,1,0)
        self.grid2.addWidget(self.btn_Stop_Posion,1,5)


        self.form0  = QGridLayout()
        self.form0.addWidget(self.movie_screen,0,0)
        self.form0.addWidget(self.tables,0,0)

        self.layout = QHBoxLayout()
        self.layout.addWidget(self.myListDns)
        self.layout.addLayout(self.layoutform)

        self.form.addRow(self.grid0)
        self.form.addRow(self.grid1)
        self.form.addRow(self.grid2)

        self.Main.addLayout(self.form0)
        self.Main.addLayout(self.layout)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def SettingsGUI(self):
        ifaces = self.interfaces
        for i,j in enumerate(ifaces['all']):
            if ifaces['all'][i] != '':
                self.ComboIface.addItem(ifaces['all'][i])
        if ifaces['gateway'] != None:
            self.txt_gateway.setText(ifaces['gateway'])
            self.txt_redirect.setText(ifaces['IPaddress'])
        try:
            items = ['example.com:{}'.format(gethostbyname('example.com')),]
            for i in items:
                item = QListWidgetItem()
                item.setText(i)
                item.setSizeHint(QSize(30,30))
                self.myListDns.addItem(item)
        except Exception:
            pass

    def listItemclicked(self,pos):
        item = self.myListDns.selectedItems()
        self.listMenu= QMenu()
        menu = QMenu()
        additem = menu.addAction('Add Host')
        removeitem = menu.addAction('Remove Host')
        clearitem = menu.addAction('clear all')
        action = menu.exec_(self.myListDns.viewport().mapToGlobal(pos))
        if action == removeitem:
            if item != []:
                self.myListDns.takeItem(self.myListDns.currentRow())
        elif action == additem:
            text, resp = QInputDialog.getText(self, 'Add DNS',
            'Enter the DNS and IP for spoof hosts: ex: facebook.com:31.13.65.1')
            if resp:
                try:
                    host, ip = text.split(':')
                    itemsexits = []
                    for index in xrange(self.myListDns.count()):
                        itemsexits.append(str(self.myListDns.item(index).text()))
                    for i in itemsexits:
                        if search(str(host+':'+ip),i):
                            QMessageBox.information(self,'Dns Rsolver','this DNS already exist on List Attack')
                            return
                    item = QListWidgetItem()
                    item.setText(host+':'+ip)
                    item.setSizeHint(QSize(30,30))
                    self.myListDns.addItem(item)
                except gaierror,e:
                    QMessageBox.information(self,'error',str(e))
                    return
        elif action == clearitem:
            self.myListDns.clear()

    def discoveryIface(self):
        iface = str(self.ComboIface.currentText())
        if self.configure.xmlSettings('statusAP','value',None,False) == 'True':
            self.txt_gateway.setText('10.0.0.1')
        ip = Refactor.get_Ipaddr(iface)
        self.txt_redirect.setText(ip)


    def thread_scan_reveice(self,info_ip):
        self.StatusMonitor(False,'stas_scan')
        self.movie_screen.setDisabled(False)
        self.tables.setVisible(True)
        data = info_ip.split('|')
        Headers = []
        self.data['IPaddress'].append(data[0])
        self.data['MacAddress'].append(data[1])
        self.data['Hostname'].append(data[2])
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


    def show_frm_fake(self):
        self.n = frm_update_attack()
        self.n.setGeometry(QRect(100, 100, 450, 300))
        self.n.show()

    def emit_template(self,log):
        if log == 'started':
            self.StatusMonitor(True,'stas_phishing')

    def show_template_dialog(self):
        self.connect(self.Ftemplates,SIGNAL('Activated ( QString ) '), self.emit_template)
        self.Ftemplates.txt_redirect.setText(self.txt_redirect.text())
        self.Ftemplates.show()

    def kill_attack(self):
        if hasattr(self, 'Ftemplates'):
            self.Ftemplates.killThread()
        if hasattr(self,'ThreadScanner'):
            self.ThreadScanner.terminate()
        for i in self.ThreadDirc['dns_spoof']:i.stop()
        for i in threadloading['arps']:i.stop()
        threadloading['template'] = []
        threadloading['arps'] = []
        self.ThreadDirc['dns_spoof'] = []
        self.StatusMonitor(False,'dns_spoof')
        self.StatusMonitor(False,'stas_phishing')
        chdir(self.owd)

    @pyqtSlot(QModelIndex)
    def check_options(self,index):
        if self.check_face.isChecked():
            self.check_route.setChecked(False)
            self.check_gmail.setChecked(False)

        elif self.check_gmail.isChecked():
            self.check_face.setChecked(False)
            self.check_route.setChecked(False)
        else:
            self.check_face.setChecked(False)
            self.check_gmail.setChecked(False)

    def StopArpAttack(self,data):
        if data == 'finished':
            self.StatusMonitor(False,'dns_spoof')
    def Start_Attack(self):
        self.targets = {}
        if (len(self.txt_target.text()) and  len(self.txt_gateway.text())) == 0:
            QMessageBox.warning(self, 'Error Dnsspoof', 'you need set the input correctly')
        else:
            if (len(self.txt_target.text()) and len(self.txt_gateway.text())) and len(self.txt_redirect.text()) != 0:
                if len(self.txt_redirect.text()) != 0:
                    self.domains = []
                    if self.myListDns.count() != 0:
                        for index in xrange(self.myListDns.count()):
                            self.domains.append(str(self.myListDns.item(index).text()))
                        for i in self.domains:
                            self.targets[i.split(':')[0]] = (i.split(':')[1]).replace('\n','')
                    if self.configure.xmlSettings('statusAP','value',None,False) == 'False':
                        Refactor.set_ip_forward(1)

                        arp_gateway = ThARP_posion(str(self.txt_target.text()),str(self.txt_gateway.text()),
                        get_if_hwaddr(str(self.ComboIface.currentText())))
                        arp_gateway.setObjectName('Arp Posion:: [gateway]')
                        threadloading['arps'].append(arp_gateway)
                        arp_gateway.start()

                        arp_target = ThARP_posion(str(self.txt_gateway.text()),str(self.txt_target.text()),
                        get_if_hwaddr(str(self.ComboIface.currentText())))
                        arp_target.setObjectName('Arp Posion:: [target]')
                        threadloading['arps'].append(arp_target)
                        arp_target.start()

                    if self.myListDns.count() == 0:self.targets = ''
                    thr = ThSpoofAttack(self.targets,
                    str(self.ComboIface.currentText()),'udp port 53',True,str(self.txt_redirect.text()))
                    if self.configure.xmlSettings('statusAP','value',None,False) == 'False':thr.redirection()
                    else:thr.redirectionAP()
                    self.connect(thr,SIGNAL('Activated ( QString ) '), self.StopArpAttack)
                    thr.setObjectName('Dns Spoof')
                    self.ThreadDirc['dns_spoof'].append(thr)
                    self.StatusMonitor(True,'dns_spoof')
                    thr.start()


    def Start_scan(self):
        self.StatusMonitor(True,'stas_scan')
        threadscan_check = self.configure.xmlSettings('advanced','Function_scan',None,False)
        self.tables.clear()
        self.data = {'IPaddress':[], 'Hostname':[], 'MacAddress':[]}
        if threadscan_check == 'Nmap':
            try:
                from nmap import PortScanner
            except ImportError:
                QMessageBox.information(self,'Error Nmap','The modules python-nmap not installed')
                return
            if self.txt_gateway.text() != '':
                self.movie_screen.setDisabled(True)
                self.tables.setVisible(False)
                config_gateway = str(self.txt_gateway.text())
                scan = ''
                config_gateway = config_gateway.split('.')
                del config_gateway[-1]
                for i in config_gateway:
                    scan += str(i) + '.'
                self.ThreadScanner = ThreadScan(scan + '0/24')
                self.connect(self.ThreadScanner,SIGNAL('Activated ( QString ) '), self.thread_scan_reveice)
                self.StatusMonitor(True,'stas_scan')
                self.ThreadScanner.start()
            else:
                QMessageBox.information(self,'Error in gateway','gateway not found.')

        elif threadscan_check == 'Ping':
            if self.txt_gateway.text() != '':
                config = str(self.txt_gateway.text())
                t = threading.Thread(target=self.scanner_network,args=(config,))
                t.daemon = True
                t.start(),t.join()
                self.StatusMonitor(False,'stas_scan')
            else:
                QMessageBox.information(self,'Error in gateway','gateway not found.')
        else:
            QMessageBox.information(self,'Error on select thread Scan','thread scan not selected.')

    def working(self,ip,lista):
        with open(devnull, 'wb') as limbo:
            result=Popen(['ping', '-c', '1', '-n', '-W', '1', ip],
            stdout=limbo, stderr=limbo).wait()
            if not result:
                print('online',ip)
                lista[ip] = ip + '|' + self.module_network.get_mac(ip)

    def scanner_network(self,gateway):
        scan = ''
        config_gateway = gateway.split('.')
        del config_gateway[-1]
        for i in config_gateway:
            scan += str(i) + '.'
        gateway = scan
        ranger = str(self.ip_range.text()).split('-')
        jobs = []
        manager = Manager()
        on_ips = manager.dict()
        for n in xrange(int(ranger[0]),int(ranger[1])):
            ip='%s{0}'.format(n)%(gateway)
            p = Process(target=self.working,args=(ip,on_ips))
            jobs.append(p)
            p.start()
        for i in jobs: i.join()
        for i in on_ips.values():
            Headers = []
            n = i.split('|')
            self.data['IPaddress'].append(n[0])
            self.data['MacAddress'].append(n[1])
            self.data['Hostname'].append('<unknown>')
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

    def Stop_scan(self):
        self.ThreadScanner.terminate()
        self.StatusMonitor(False,'stas_scan')
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)
        self.tables.setVisible(True)

    def StatusMonitor(self,bool,wid):
        if bool and wid == 'stas_scan':
            self.txt_status_scan.setText('[ ON ]')
            self.txt_status_scan.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'stas_scan':
            self.txt_status_scan.setText('[ OFF ]')
            self.txt_status_scan.setStyleSheet('QLabel {  color : red; }')
        elif bool and wid == 'dns_spoof':
            self.txt_statusarp.setText('[ ON ]')
            self.txt_statusarp.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'dns_spoof':
            self.txt_statusarp.setText('[ OFF ]')
            self.txt_statusarp.setStyleSheet('QLabel {  color : red; }')
        elif bool and wid == 'stas_phishing':
            self.txt_status_phishing.setText('[ ON ]')
            self.txt_status_phishing.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'stas_phishing':
            self.txt_status_phishing.setText('[ OFF ]')
            self.txt_status_phishing.setStyleSheet('QLabel {  color : red; }')

    @pyqtSlot(QModelIndex)
    def list_clicked_scan(self, index):
        item = self.tables.selectedItems()
        if item != []:
            self.txt_target.setText(item[0].text())
        else:
            self.txt_target.clear()
