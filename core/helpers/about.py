from core.loaders.models.PackagesUI import *

class License(QTextEdit):
    def __init__(self,parent = None):
        super(License,self).__init__(parent)
        self.setReadOnly(True)
        self.setWindowTitle('License WiFI-Pumpkin GPL')
        self.setGeometry(0,0,300,300)
        self.center()
        self.setText(open('LICENSE','r').read())
    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

class ChangeLog(QTextEdit):
    def __init__(self,parent = None):
        super(ChangeLog,self).__init__(parent)
        self.setMinimumHeight(240)
        self.setStyleSheet('''QWidget {
        color: #b1b1b1; background-color: #323232;}''')
        self.setText(open('CHANGELOG','r').read())
        self.setReadOnly(True)


class SettingsTranks(QVBoxLayout):
    def __init__(self,parent = None):
        super(SettingsTranks, self).__init__(parent)
        self.mainLayout    = QFormLayout()
        self.scrollwidget = QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)

        self.formMode = QFormLayout()
        self.formMode.addRow(QLabel('<a href="https://github.com/mitmproxy/mitmproxy"><strong>@mitmproxy</strong></a>'))
        self.formMode.addRow(QLabel('ProxyServer tranparent HTTP proxy <br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/TimSchumi"><strong>@TimSchumi</strong></a>'))
        self.formMode.addRow(QLabel('Debian package build and password improvements <br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/psychomario"><strong>@psychomario</strong></a>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/psychomario/PyPXE">PyPXE</a> class implements a DHCP Server<br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/xtr4nge"><strong>@xtr4nge</strong></a>'))
        self.formMode.addRow(QLabel('PLugin <a href="https://github.com/xtr4nge/sslstrip">Sslstrip</a> fork inject code<br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/LeonardoNve"><strong>@LeonardoNve</strong></a>'))
        self.formMode.addRow(QLabel('Plugin <a href="https://github.com/LeonardoNve/sslstrip2">SSLstrip2</a> version fork'))
        self.formMode.addRow(QLabel('Plugin <a href="https://github.com/LeonardoNve/dns2proxy">Dns2proxy</a> Offensive DNS server <br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/davinerd"><strong>@davinerd</strong></a>'))
        self.formMode.addRow(QLabel('Plugin <a href="https://github.com/davinerd/BDFProxy-ng"> BDFProxy-ng</a> version fork <br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/lgandx"><strong> Laurent Gaffie @lgandx</strong></a>'))
        self.formMode.addRow(QLabel('Plugin <a href="https://github.com/lgandx/Responder"> Responder</a><br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/supernothing"><strong>Ben Schmidt @supernothing</strong></a>'))
        self.formMode.addRow(QLabel('Plugin <a href="https://github.com/supernothing/sergio-proxy">SergioProxy</a> - bypass HSTS<br>'))
        self.formMode.addRow(QLabel('<a href="http://www.yasinuludag.com/darkorange.stylesheet"><strong>Yasin Uludag</strong></a>'))
        self.formMode.addRow(QLabel('theme1.qss - Qt dark orange stylesheet<br>'))
        self.formMode.addRow(QLabel('<a href="https://github.com/ColinDuquesnoy/QDarkStyleSheet"><strong>Colin Duquesnoy @ColinDuquesnoy</strong></a>'))
        self.formMode.addRow(QLabel('theme2.qss - Qt dark blue stylesheet<br>'))
        self.mainLayout.addRow(self.formMode)

        self.layout = QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.addLayout(self.layout)

class frmAbout(PumpkinModule):
    def __init__(self,author,emails,version,
        update,license,desc, parent = None):
        super(frmAbout, self).__init__(parent)
        self.author      = author
        self.emails      = emails
        self.version     = version
        self.update      = update
        self.desc        = QLabel(desc[0]+'<br>')
        self.setWindowTitle("About WiFi-Pumpkin")
        self.Main = QVBoxLayout()
        self.frm = QFormLayout()
        self.setGeometry(0, 0, 350, 400)
        self.center()
        self.loadtheme(self.configure.XmlThemeSelected())
        self.Qui_update()

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def Qui_update(self):
        self.logoapp = QLabel('')
        self.logoapp.setPixmap(QPixmap('icons/icon.ico').scaled(96,96))
        self.form = QFormLayout()
        self.form2 = QHBoxLayout()
        self.form.addRow(self.logoapp,QLabel(
        QString('<h2>WiFi-Pumpkin {}</h2>'.format(self.version))))
        self.tabwid = QTabWidget(self)
        self.TabAbout = QWidget(self)
        self.TabVersion = QWidget(self)
        self.TabTranks  = QWidget(self)
        self.TabChangelog = QWidget(self)
        self.TabDonate   = QWidget(self)
        self.btn_exit = QPushButton("Close")
        self.btn_exit.setFixedWidth(90)
        self.btn_exit.setIcon(QIcon('icons/cancel.png'))
        self.btn_exit.clicked.connect(self.close)

        self.formAbout = QFormLayout()
        self.formVersion = QFormLayout()
        self.formTranks = QFormLayout()
        self.formChange = QFormLayout()
        self.formDonate = QFormLayout()

        # About section
        self.formAbout.addRow(self.desc)
        self.formAbout.addRow(QLabel('Last Update:'))
        self.formAbout.addRow(QLabel(self.update+'<br>'))
        self.formAbout.addRow(QLabel('Feedback:'))
        self.formAbout.addRow(QLabel(self.emails[0]))
        self.formAbout.addRow(QLabel(self.emails[1]+'<br>'))
        self.formAbout.addRow(QLabel('Copyright 2015-2017, '+self.author[:-14]))
        self.gnu = QLabel('<a href="link">License: GNU General Public License Version</a><br>')
        self.gnu.linkActivated.connect(self.link)
        self.formAbout.addRow(self.gnu)
        self.formAbout.addRow(QLabel('<center>{}</center>'.format(self.author[-14:])))
        self.TabAbout.setLayout(self.formAbout)

        #Donate section
        self.formDonate.addRow(QLabel('Open source project require developer time.<br>'
        ' You need dev time to fix bugs, you need dev time<br> to add features,'
        " thank you for your contribution! "))
        self.imagePay =  QLabel()
        self.imagePay.setPixmap(QPixmap('icons/donatepay.gif'))
        self.formDonate.addRow(QLabel(''))
        self.formDonate.addRow(QLabel('Support Donations:'))
        self.formDonate.addRow(self.imagePay)
        self.formDonate.addRow(QLabel('Paypal:'),QLabel('<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick'
        '&hosted_button_id=PUPJEGHLJPFQL">WiFi-Pumpkin project - Paypal Donataion </a>'))
        self.formDonate.addRow(QLabel('BTC:'),QLabel('<a href="1HBXz6XX3LcHqUnaca5HRqq6rPUmA3pf6f">1HBXz6XX3LcHqUnaca5HRqq6rPUmA3pf6f</a>'))
        self.formDonate.addRow(QLabel('Patreon:'),QLabel('<a href="https://www.patreon.com/wifipumpkin">https://www.patreon.com/wifipumpkin</a>'))
        self.TabDonate.setLayout(self.formDonate)

        # Version Section
        self.formVersion.addRow(QLabel('<strong>Version: {}</strong><br>'.format(self.version)))
        self.formVersion.addRow(QLabel('Using:'))
        import platform
        python_version = platform.python_version()
        self.formVersion.addRow(QLabel('''
        <ul>
          <li>QTVersion: {}</li>
          <li>Python: {}</li>
        </ul>'''.format(QT_VERSION_STR,python_version)))
        self.TabVersion.setLayout(self.formVersion)

        # Tranks Section
        self.TabpageTranks = QVBoxLayout(self.TabTranks)
        self.formTE = SettingsTranks()
        self.TabpageTranks.addLayout(self.formTE)

        # Changelog Section
        self.formChange.addRow(ChangeLog())
        self.TabChangelog.setLayout(self.formChange)

        # self.form.addRow(self.btn_exit)
        self.tabwid.addTab(self.TabAbout,'About')
        self.tabwid.addTab(self.TabVersion,'Version')
        self.tabwid.addTab(self.TabChangelog,'ChangeLog')
        self.tabwid.addTab(self.TabTranks,'TranksTo')
        self.tabwid.addTab(self.TabDonate, 'Donate')
        self.form.addRow(self.tabwid)
        self.form2.addSpacing(240)
        self.form2.addWidget(self.btn_exit)
        self.form.addRow(self.form2)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def link(self):
        self.formLicense = License()
        self.formLicense.show()
