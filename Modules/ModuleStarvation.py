#The MIT License (MIT)
#Copyright (c) 2015-2016 mh4x0f P0cL4bs Team
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in
#the Software without restriction, including without limitation the rights to
#use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
#the Software, and to permit persons to whom the Software is furnished to do so,
#subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
#FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.Settings import frm_Settings
from Modules.utils import Refactor,ThreadAttackStar

class frm_dhcp_main(QMainWindow):
    def __init__(self, parent=None):
        super(frm_dhcp_main, self).__init__(parent)
        self.form_widget = frm_dhcp_Attack(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("DHCP Starvation Attack")
        self.setWindowIcon(QIcon('rsc/icon.ico'))

        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

class frm_dhcp_Attack(QWidget):
    def __init__(self, parent=None):
        super(frm_dhcp_Attack, self).__init__(parent)
        self.Main       = QVBoxLayout()
        self.control    = None
        self.GUI()
    def GUI(self):
        self.form       = QFormLayout()
        self.list_log   = QListWidget()
        self.check      = QLabel("")
        self.btn_Start_attack   = QPushButton("Start Attack",self)
        self.btn_Stop_attack    = QPushButton("Stop Attack",self)
        self.check.setText("[ OFF ]")
        self.check.setStyleSheet("QLabel {  color : red; }")

        self.btn_Start_attack.clicked.connect(self.D_attack)
        self.btn_Stop_attack.clicked.connect(self.kill_thread)

        self.btn_Start_attack.setIcon(QIcon("rsc/start.png"))
        self.btn_Stop_attack.setIcon(QIcon("rsc/Stop.png"))

        self.form.addRow(self.list_log)
        self.form.addRow("Status Attack:",self.check)
        self.form.addRow(self.btn_Start_attack, self.btn_Stop_attack)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)


    def getloggerAttack(self,log):
        self.list_log.addItem(log)

    def D_attack(self):
        interface = Refactor.get_interfaces()['activated']
        if interface != None:
            self.check.setText("[ ON ]")
            self.check.setStyleSheet("QLabel {  color : green; }")
            self.threadstar = ThreadAttackStar(interface)
            self.connect(self.threadstar,SIGNAL("Activated ( QString )"),self.getloggerAttack)
            self.threadstar.setObjectName("DHCP Starvation")
            self.threadstar.start()
            return
        QMessageBox.information(self, 'Interface Not found', 'None detected network interface try again.')

    def attack_OFF(self):
        self.check.setStyleSheet("QLabel {  color : red; }")

    def kill_thread(self):
        self.threadstar.stop()
        self.attack_OFF()
        self.list_log.clear()