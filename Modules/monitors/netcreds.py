from os import getcwd,path
from Core.loaders.Stealth.PackagesUI import *


class frm_NetCredsLogger(PumpkinModule):
    def __init__(self, parent = None):
        super(frm_NetCredsLogger, self).__init__(parent)
        self.setGeometry(0, 0, 550, 400)
        self.Main       = QVBoxLayout(self)
        self.owd        = getcwd()
        self.thread     = []
        self.loadtheme(self.configure.XmlThemeSelected())
        self.center()
        self.Qui()

    def Start_Get_creds(self):
        self.listDns.clear()
        self.list_creds.clear()
        # Thread Capture logs
        creds = ThreadPopen(['tail','-f','Logs/AccessPoint/credentials.log'])
        self.connect(creds,SIGNAL('Activated ( QString ) '), self.loggercreds)
        creds.setObjectName('Netcreds::Credentials')
        urls = ThreadPopen(['tail','-f','Logs/AccessPoint/urls.log'])
        self.connect(urls,SIGNAL('Activated ( QString ) '), self.loggerurls)
        urls.setObjectName('Netcreds::Urls')
        if path.exists('Logs/AccessPoint/credentials.log'):
            self.thread.append(creds)
            creds.start()
        if path.exists('Logs/AccessPoint/urls.log'):
            self.thread.append(urls)
            urls.start()
        if not urls.isRunning():
            QMessageBox.warning(self,'error logger read','netcreds no logger found.')

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