from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.config.Settings import frm_Settings
from Modules.utils import ThreadPopen
from os import chdir,getcwd,path

class frm_get_credentials(QDialog):
    def __init__(self, parent = None):
        super(frm_get_credentials, self).__init__(parent)
        self.label = QLabel()
        self.Main = QVBoxLayout(self)
        self.setGeometry(0, 0, 450, 200)
        self.center()
        self.owd = getcwd()
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.Qui()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def SearchCreds(self,path,page):
        self.list_password.clear()
        chdir(self.owd)
        log = open(path, 'r')
        try:
            for i,j in enumerate(log.readlines()):
                s = j.split('-')
                self.list_password.addItem(page+': Email: ' +s[0] + '   Password: ' +s[1])
        except:
            QMessageBox.information(self,'Error get data','nothing captured from '+page)

    def Start_Get_creds(self):
        if self.radio_face.isChecked():
            self.SearchCreds('Templates/Phishing/Facebook/log.txt','Facebook')
        elif self.radio_gmail.isChecked():
            self.SearchCreds('Templates/Phishing/Gmail/log.txt','Gmail')
        elif self.radio_route.isChecked():
            self.SearchCreds('Templates/Phishing/Route/log.txt','Router')

    def Qui(self):
        self.frm0 = QFormLayout(self)
        self.list_password = QListWidget(self)
        self.list_password.setFixedHeight(200)

        self.btn_getdata = QPushButton('get data')
        self.btn_getdata.clicked.connect(self.Start_Get_creds)
        self.btn_exit = QPushButton('Exit')
        self.btn_exit.clicked.connect(self.deleteLater)

        self.radio_face  = QRadioButton('Facebook')
        self.radio_gmail = QRadioButton('Gmail')
        self.radio_route = QRadioButton('Router')
        self.grid_radio = QGridLayout(self)
        self.grid_radio.addWidget(self.radio_face,0,0)
        self.grid_radio.addWidget(self.radio_gmail,0,1)
        self.grid_radio.addWidget(self.radio_route,0,2)
        self.frm0.addRow(self.list_password)
        self.frm0.addRow(self.grid_radio)
        self.frm0.addRow(self.btn_getdata)
        self.frm0.addRow(self.btn_exit)
        self.Main.addLayout(self.frm0)
        self.setLayout(self.Main)


class frm_NetCredsLogger(QDialog):
    def __init__(self, parent = None):
        super(frm_NetCredsLogger, self).__init__(parent)
        self.setGeometry(0, 0, 550, 400)
        self.Main       = QVBoxLayout(self)
        self.owd        = getcwd()
        self.thread     = []
        self.config     = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.center()
        self.Qui()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def Start_Get_creds(self):
        self.listDns.clear()
        self.list_creds.clear()
        # Thread Capture logs
        creds = ThreadPopen(['tail','-f','Logs/credentials.log'])
        self.connect(creds,SIGNAL('Activated ( QString ) '), self.loggercreds)
        creds.setObjectName('Netcreds::Credentials')
        urls = ThreadPopen(['tail','-f','Logs/urls.log'])
        self.connect(urls,SIGNAL('Activated ( QString ) '), self.loggerurls)
        urls.setObjectName('Netcreds::Urls')
        if path.exists('Logs/credentials.log'):
            self.thread.append(creds)
            creds.start()
        if path.exists('Logs/urls.log'):
            self.thread.append(urls)
            urls.start()
        if not urls.isRunning():
            QMessageBox.warning(self,'error logger read','netcreds::url no logger found.')
        if not creds.isRunning():
            QMessageBox.warning(self,'error logger read','netcreds::creds not logger found.')

    def loggercreds(self,data):
        self.list_creds.addItem(data)
        self.list_creds.scrollToBottom()
    def loggerurls(self,data):
        self.listDns.addItem(data)
        self.listDns.scrollToBottom()

    def exit_function(self):
        for i in self.thread:i.stop()
        self.deleteLater()
    def Qui(self):
        self.frm0 = QFormLayout(self)
        self.listDns = QListWidget(self)
        self.listDns.setAutoScroll(True)
        self.list_creds = QListWidget(self)
        self.list_creds.setAutoScroll(True)

        self.btn_getdata = QPushButton('Capture logs')
        self.btn_getdata.clicked.connect(self.Start_Get_creds)
        self.btn_exit = QPushButton('Exit')
        self.btn_exit.clicked.connect(self.exit_function)

        self.frm0.addRow(self.listDns)
        self.frm0.addRow(self.list_creds)

        self.frm0.addRow(self.btn_getdata)
        self.frm0.addRow(self.btn_exit)
        self.Main.addLayout(self.frm0)
        self.setLayout(self.Main)


class frm_dns2proxy(QDialog):
    def __init__(self, parent = None):
        super(frm_dns2proxy, self).__init__(parent)
        self.setGeometry(0, 0, 400, 400)
        self.Main       = QVBoxLayout(self)
        self.owd        = getcwd()
        self.thread     = []
        self.config     = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.center()
        self.Qui()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def Start_Get_creds(self):
        self.listDns.clear()
        # Thread Capture logs
        if path.exists('Logs/dns2proxy.log'):
            dns = ThreadPopen(['tail','-f','Logs/dns2proxy.log'])
            self.connect(dns,SIGNAL('Activated ( QString ) '), self.loggerdns)
            dns.setObjectName('Dns2proxy::Capture')
            self.thread.append(dns)
            dns.start()
            return
        QMessageBox.warning(self,'error dns2proxy logger','dns2proxy::capture no logger found')


    def loggerdns(self,data):
        self.listDns.addItem(data)
        self.listDns.scrollToBottom()

    def exit_function(self):
        for i in self.thread:i.stop()
        self.deleteLater()
    def Qui(self):
        self.frm0 = QFormLayout(self)
        self.listDns = QListWidget(self)
        self.listDns.adjustSize()
        self.listDns.setFixedHeight(320)
        self.listDns.setAutoScroll(True)

        self.btn_getdata = QPushButton('Capture logs')
        self.btn_getdata.clicked.connect(self.Start_Get_creds)
        self.btn_exit = QPushButton('Exit')
        self.btn_exit.clicked.connect(self.exit_function)

        self.frm0.addWidget(self.listDns)

        self.frm0.addRow(self.btn_getdata)
        self.frm0.addRow(self.btn_exit)
        self.Main.addLayout(self.frm0)
        self.setLayout(self.Main)