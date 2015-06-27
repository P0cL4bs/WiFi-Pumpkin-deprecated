from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.Settings import frm_Settings
class frm_Update(QDialog):
    def __init__(self, parent = None):
        super(frm_Update, self).__init__(parent)
        self.setWindowTitle("Update Center")
        self.Main = QVBoxLayout()
        self.frm = QFormLayout()
        self.setGeometry(0, 0, 200, 100)
        self.center()
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.Qui_update()
    def loadtheme(self,theme):
        if theme != "theme2":
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
        else:
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def Qui_update(self):
        self.form = QFormLayout(self)
        self.btn_update = QPushButton("check")
        self.form.addRow(self.btn_update)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)