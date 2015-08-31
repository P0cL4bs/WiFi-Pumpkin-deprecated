from PyQt4.QtGui import *
from subprocess import Popen, PIPE
from Core.Settings import frm_Settings
from os import popen
from re import search
import getpass

class frm_privelege(QDialog):
    def __init__(self, parent = None):
        super(frm_privelege, self).__init__(parent)
        self.setWindowTitle("Privilege Authentication")
        self.Main = QVBoxLayout()
        self.frm = QFormLayout()
        self.setGeometry(0, 0, 270, 100)
        self.center()
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

    def Qui(self):
        self.user = QComboBox()
        self.user.addItem(getpass.getuser())
        self.btn_cancel = QPushButton("Cancel")
        self.btn_ok = QPushButton("Ok")
        self.Editpassword = QLineEdit(self)
        self.Editpassword.setFocus()
        #temporary

        self.Editpassword.setEchoMode(QLineEdit.Password)
        self.btn_cancel.clicked.connect(self.close)
        self.btn_ok.clicked.connect(self.function_ok)
        self.btn_ok.setDefault(True)
        self.frm.addRow("User:", self.user)
        self.frm.addRow("Password:", self.Editpassword)
        self.grid = QGridLayout()
        self.grid.addWidget(self.btn_cancel, 1,2)
        self.grid.addWidget(self.btn_ok, 1,3)
        self.Main.addLayout(self.frm)
        self.Main.addLayout(self.grid)
        self.setLayout(self.Main)

    def function_ok(self):
        self.hide()
        out = self.thread(str(self.Editpassword.text()))
        if search("1 incorrect password attemp",out):
            QMessageBox.information(self, "Sudo Password check",
            "[sudo] password for %s: Sorry, try again."%(getpass.getuser()))
            self.show()
            self.Editpassword.clear()
            return
        self.close()

    def thread(self,sudo_password):
        popen("sudo -k")
        p = Popen(['sudo', '-S','|','ls'], stdin=PIPE, stderr=PIPE,
        universal_newlines=True)
        output = p.communicate(str(sudo_password) + '\n')[1]
        return output