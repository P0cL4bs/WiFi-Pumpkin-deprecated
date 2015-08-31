from PyQt4.QtGui import *
from Core.Settings import frm_Settings
class frmAbout(QDialog):
    def __init__(self,author,emails,version,
        date_create,update,license,desc, parent = None):
        super(frmAbout, self).__init__(parent)
        self.author      = author
        self.emails      = emails
        self.version     = version
        self.date_create = date_create
        self.update      = update
        self.license     = license
        self.desc        = desc
        self.setWindowTitle("About 3vilTwinAttacker")
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
        self.licenseEdit.setText(
            '''The MIT License (MIT)
Copyright (c) 2015-2016 mh4x0f P0cL4bs Team
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'''
        )
        ltool  = QLabel('<center>3vilTwin-Attacker v%s</center>'%(self.version))
        ldesc = QLabel('<center>'+self.desc[0]+'</center>')
        lversion = QLabel('Version:'+self.version)
        lupdate = QLabel('Last Update:'+self.update)
        lautor = QLabel('author:'+self.author)
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
