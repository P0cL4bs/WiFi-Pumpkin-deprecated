from os import chdir,getcwd,path
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.config.Settings import frm_Settings
from Core.Utils import ThreadPopen

class frm_get_credentials(QDialog):
    def __init__(self, parent = None):
        super(frm_get_credentials, self).__init__(parent)
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