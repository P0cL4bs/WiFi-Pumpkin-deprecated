from Core.loaders.Stealth.PackagesUI import *

class frmAbout(PumpkinModule):
    def __init__(self,author,emails,version,
        update,license,desc, parent = None):
        super(frmAbout, self).__init__(parent)
        self.author      = author
        self.emails      = emails
        self.version     = version
        self.update      = update
        self.license     = license
        self.desc        = desc
        self.setWindowTitle("About WiFi-Pumpkin")
        self.Main = QVBoxLayout()
        self.frm = QFormLayout()
        self.setGeometry(0, 0, 400, 300)
        self.center()
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.Qui_update()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def Qui_update(self):
        self.form = QFormLayout(self)
        self.btn_exit = QPushButton("Close")
        self.licenseEdit = QTextEdit(self)
        self.licenseEdit.setFixedHeight(150)
        self.licenseEdit.setText(open('LICENSE','r').read())
        ltool  = QLabel('<center>WiFi-Pumpkin v%s</center>'%(self.version))
        ldesc = QLabel('<center>'+self.desc[0]+'</center>')
        lversion = QLabel('Version:'+self.version)
        lupdate = QLabel('Last Update:'+self.update)
        lautor = QLabel('Author:'+self.author)
        lemail = QLabel('Emails:'+self.emails[0] +" | "+self.emails[1])
        licese = QLabel('License:'+self.license)
        self.form.addRow(ltool)
        self.form.addRow(ldesc)
        self.form.addRow(lversion)
        self.form.addRow(lupdate)
        self.form.addRow(lautor)
        self.form.addRow(lemail)
        self.form.addRow(licese)
        self.form.addRow(self.licenseEdit)
        self.btn_exit.clicked.connect(self.deleteLater)
        self.form.addRow(self.btn_exit)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)
