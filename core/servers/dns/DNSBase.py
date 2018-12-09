import weakref
from core.config.globalimport import *
from core.widgets.default.uimodel import *
from core.widgets.docks.dock import *
from core.widgets.default.SessionConfig import SessionConfig
from core.utility.component import ComponentBlueprint
from core.utility.threads import (ProcessThread)


class DNSBase(QtGui.QWidget,ComponentBlueprint):
    Name = "DNSBaseClass"
    ID = "DNSBase"
    ConfigRoot="DNSServer"
    ExecutableFile = ""
    hasPreference = False
    arguments =[['label','switch','type','defaultvalue','enabled','required'],
                ]

    addDock = QtCore.pyqtSignal(object)
    def __init__(self,parent,**kwargs):
        super(DNSBase,self).__init__(parent)
        self.parent = parent
        self.FSettings = SuperSettings.getInstance()
        self.SessionConfig = SessionConfig.getInstance()
        self.dockwidget = DNSDock(self,title=self.Name)
        self.reactor = None
        self.LogFile ="logs/AccessPoint/{}.log".format(self.ID)
        self.DialogParams = OptionDialog(self)

        setup_logger(self.Name, self.LogFile, self.parent.currentSessionID)
        self.logger = getLogger(self.Name)

        self.btnsettings = QtGui.QPushButton("Parameters")
        self.btnsettings.clicked.connect(self.showarguments)
        self.btnsettings.setMaximumWidth(100)
        self.btnsettings.setMaximumHeight(30)
        self.controlui = QtGui.QRadioButton("{}".format(self.Name))
        self.controlui.toggled.connect(self.controluiCallback)
        self.controlui.setChecked(self.FSettings.Settings.get_setting(self.ConfigRoot,self.ID,format=bool))
        self.controluiCallback()
    def showarguments(self):
        self.DialogParams.show()

    def controluiCallback(self):
        self.FSettings.Settings.set_setting(self.ConfigRoot,
                                            self.ID, self.controlui.isChecked())
        self.btnsettings.setEnabled(self.controlui.isChecked())
        self.dockwidget.addDock.emit(self.controlui.isChecked())
    @property
    def commandargs(self):
        pass
    @property
    def command(self):
        cmdpath = os.popen('which {}'.format(self.ExecutableFile)).read().split('\n')[0]
        if cmdpath:
            return cmdpath
        else:
            return None
    def boot(self):
        self.reactor = ProcessThread({self.command: self.commandargs})
        self.reactor._ProcssOutput.connect(self.LogOutput)
        self.reactor.setObjectName(self.Name)  # use dns2proxy as DNS server
    def LogOutput(self,data):
        if self.FSettings.Settings.get_setting('accesspoint', 'statusAP', format=bool):
            try:
                data = str(data).split(' : ')[1]
                for line in data.split('\n'):
                    if len(line) > 2 and not self.parent.currentSessionID in line:
                        self.dockwidget.writeModeData(line)
                        self.logger.info(line)
            except IndexError:
                return None


class DNSSettings(CoreSettings):
    Name = "DNS Server"
    ID = "DNSSettings"
    Category = "DNS"
    instances =[]

    def __init__(self,parent=None):
        super(DNSSettings,self).__init__(parent)
        self.__class__.instances.append(weakref.proxy(self))
        self.setCheckable(False)
        self.forml = QtGui.QFormLayout()
        self.dnslist = [dns(self.parent) for dns in DNSBase.__subclasses__()]
        for dns in self.dnslist:
            if dns.hasPreference:
                self.forml.addRow(dns.controlui,dns.btnsettings)
            else:
                self.forml.addRow(dns.controlui)
        self.layout.addLayout(self.forml)

    @classmethod
    def getInstance(cls):
        return cls.instances[0]


class DNSDock(DockableWidget):
    def __init__(self,parent=0,title="",info={}):
        super(DNSDock,self).__init__(parent,title,info)
        self.setObjectName(title)


