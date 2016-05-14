from os import getcwd,path
from Core.loaders.Stealth.PackagesUI import *


class frm_dns2proxy(PumpkinModule):
    def __init__(self, parent = None):
        super(frm_dns2proxy, self).__init__(parent)
        self.setGeometry(0, 0, 400, 400)
        self.Main       = QVBoxLayout()
        self.owd        = getcwd()
        self.thread     = []
        self.loadtheme(self.configure.XmlThemeSelected())
        self.center()
        self.Qui()

    def Start_Get_creds(self):
        self.listDns.clear()
        # Thread Capture logs
        if path.exists('Logs/AccessPoint/dns2proxy.log'):
            dns = ThreadPopen(['tail','-f','Logs/AccessPoint/dns2proxy.log'])
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
        self.frm0 = QFormLayout()
        self.listDns = QListWidget()
        self.listDns.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.listDns.setFixedHeight(320)
        self.listDns.setAutoScroll(True)

        self.btn_getdata = QPushButton('Capture logs')
        self.btn_getdata.setIcon(QIcon('Icons/start.png'))
        self.btn_getdata.clicked.connect(self.Start_Get_creds)
        self.btn_exit = QPushButton('Kill')
        self.btn_exit.setIcon(QIcon('Icons/cancel.png'))
        self.btn_exit.clicked.connect(self.exit_function)

        self.frm0.addWidget(self.listDns)

        self.frm0.addRow(self.btn_getdata)
        self.frm0.addRow(self.btn_exit)
        self.Main.addLayout(self.frm0)
        self.setLayout(self.Main)