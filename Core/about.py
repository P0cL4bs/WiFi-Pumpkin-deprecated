from PyQt4.QtGui import *
from Core.Settings import frm_Settings
author      = ' @mh4x0f P0cl4bs Team'
emails      = ['mh4root@gmail.com','p0cl4bs@gmail.com']
version     = '0.6.3'
date_create = '18/01/2015'
update      ='07/06/2015'
license     = 'MIT License (MIT)'
desc        = ['Framework for EvilTwin Attacks']
class frmAbout(QDialog):
    def __init__(self, parent = None):
        super(frmAbout, self).__init__(parent)
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
        self.license = QTextEdit(self)
        self.license.setText(
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
        ltool  = QLabel('<center>3vilTwin-Attacker v%s</center>'%(version))
        ldesc = QLabel('<center>'+desc[0]+'</center>')
        lversion = QLabel('Version:'+version)
        lupdate = QLabel('Last Update:'+update)
        lautor = QLabel('author:'+author)
        lemail = QLabel('Emails:'+emails[0] +" | "+emails[1])
        licese = QLabel('License:'+license)
        self.form.addRow(ltool)
        self.form.addRow(ldesc)
        self.form.addRow(lversion)
        self.form.addRow(lupdate)
        self.form.addRow(lautor)
        self.form.addRow(lemail)
        self.form.addRow(licese)
        self.form.addRow(self.license)
        self.btn_exit.clicked.connect(self.deleteLater)
        self.form.addRow(self.btn_exit)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)