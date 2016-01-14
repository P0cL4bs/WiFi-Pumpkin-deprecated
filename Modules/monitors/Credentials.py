from os import getcwd,path
from Core.loaders.Stealth.PackagesUI import *

class frm_get_credentials(PumpkinModule):
    def __init__(self, parent = None):
        super(frm_get_credentials, self).__init__(parent)
        self.setGeometry(0, 0, 400, 400)
        self.Main       = QVBoxLayout(self)
        self.owd        = getcwd()
        self.thread     = []
        self.loadtheme(self.configure.XmlThemeSelected())
        self.center()
        self.Qui()

    def Start_Get_creds(self):
        self.listDns.clear()
        # Thread Capture logs
        if path.exists('Logs/Phishing/Webclone.log'):
            dns = ThreadPopen(['tail','-f','Logs/Phishing/Webclone.log'])
            self.connect(dns,SIGNAL('Activated ( QString ) '), self.loggerdns)
            dns.setObjectName('Phishing::Capture')
            self.thread.append(dns)
            dns.start()
            return
        QMessageBox.warning(self,'error Phishing logger','Phishing::capture no logger found')


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