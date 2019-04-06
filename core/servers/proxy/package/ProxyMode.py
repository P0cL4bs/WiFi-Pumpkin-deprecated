from core.widgets.docks.dock import *
from core.utility.threads import  (
    ProcessThread,
    ThreadReactor
)
from core.controllers.wirelessmodecontroller import AccessPointSettings
from core.widgets.default.uimodel import *
class Widget(QtGui.QFrame):
    def __init__(self):
        QtGui.QWidget.__init__(self)
class VBox(QtGui.QVBoxLayout):
    def __init__(self):
        QtGui.QVBoxLayout.__init__(self)

class ProxyMode(Widget,ComponentBlueprint):
    Name = "Generic"
    Author = "Wahyudin Aziz"
    Description = "Generic Placeholder for Attack Scenario"
    Icon = "icons/plugins-new.png"
    LogFile = C.LOG_ALL
    ModSettings = False
    ModType = "proxy" # proxy or server
    EXEC_PATH = ''
    _cmd_array = []
    Hidden = True
    plugins = []
    sendError = QtCore.pyqtSignal(str)
    sendSingal_disable = QtCore.pyqtSignal(object)
    addDock=QtCore.pyqtSignal(object)
    TypePlugin = 1 #  1 radio  and != 1  for checkbox


    def __init__(self,parent):
        super(ProxyMode, self).__init__()
        self.parent = parent
        self.FSettings = SuperSettings.getInstance()
        self.server = ThreadReactor()
        setup_logger(self.Name,self.LogFile,self.parent.currentSessionID)
        self.logger  = getLogger(self.Name)
        self.handler = None
        self.reactor = None
        self.subreactor = None
        self.search = {
            'sslstrip': str('iptables -t nat -A PREROUTING -p tcp' +
                            ' --destination-port 80 -j REDIRECT --to-port ' + self.FSettings.redirectport.text()),
            'dns2proxy': str('iptables -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 53'),
            'bdfproxy': str('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080'),
            'PumpkinProxy': str('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080')
            }

        self.search[self.Name]=self.iptablesrules
        self.popup = QtGui.QWidget()
        self.tabinterface = QtGui.QListWidgetItem()
        self.tabinterface.setText(self.Name)
        self.tabinterface.setSizeHint(QtCore.QSize(30, 30))
        self.tabinterface.setIcon(QtGui.QIcon(self.Icon))
        self.ConfigWindow = OptionDialog(self)
        self.ConfigWindow.setWindowTitle("{} Proxy Settings".format(self.Name))

        if (self.TypePlugin == 1):
            self.controlui = QtGui.QRadioButton(self.Name)
            self.controlui.setObjectName(QtCore.QString(self.Description))
            self.controlui.setChecked(self.FSettings.Settings.get_setting('plugins', self.Name, format=bool))
            self.controlui.toggled.connect(self.CheckOptions)
        else:
            self.controlui = QtGui.QCheckBox(self.Name)
            self.controlui.setObjectName(QtCore.QString(self.Description))
            self.controlui.setChecked(self.FSettings.Settings.get_setting('plugins', self.Name, format=bool))
            self.controlui.toggled.connect(self.CheckOptions)

        #self.controlui.clicked.connect(self.CheckOptions)
        self.setEnabled(self.FSettings.Settings.get_setting('plugins', self.Name, format=bool))

        self.btnChangeSettings = QtGui.QPushButton("None")
        self.btnChangeSettings.setEnabled(False)

        if self.ModSettings:
            self.btnChangeSettings.setEnabled(self.controlui.isChecked())
            self.btnChangeSettings.setText("Change")
            self.btnChangeSettings.setIcon(QtGui.QIcon('icons/config.png'))
            self.btnChangeSettings.clicked.connect(self.Configure)
        #TODO Update parent Proxy Status When Loading


        self.dockwidget = Dockable(None,title=self.Name)
        #self.dockwidget.addDock.emit(self.controlui.isChecked())
        self.mainLayout = QtGui.QFormLayout()
        self.scrollwidget = QtGui.QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QtGui.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)
        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(self.scroll)
    @property
    def iptablesrules(self):
        pass

    @property
    def Wireless(self):
        return AccessPointSettings.instances[0]
    def get_disable_status(self):
        if self.FSettings.Settings.get_setting('plugins', self.Name, format=bool) == True:
            if self.Name == "No Proxy":
                self.ClearRules()
                self.parent.set_proxy_statusbar('', disabled=True)
                self.sendSingal_disable.emit(self.controlui.isChecked())
                return

            self.parent.set_proxy_statusbar(self.Name)
    def onProxyEnabled(self):
        pass
    def onProxyDisabled(self):
        pass
    @property
    def hasSettings(self):
        return self.ModSettings
    def CheckOptions(self):
        self.FSettings.Settings.set_setting('plugins', self.Name, self.controlui.isChecked())
        self.dockwidget.addDock.emit(self.controlui.isChecked())
        self.get_disable_status()
        self.ClearRules()
        self.Initialize()
        if self.ModSettings:
            self.btnChangeSettings.setEnabled(self.controlui.isChecked())
        if self.controlui.isChecked() == True:
            self.setEnabled(True)
            self.onProxyEnabled()
            self.tabinterface.setText("[ {} ]".format(self.Name))

        else:
            self.onProxyDisabled()
            self.setEnabled(False)
            self.tabinterface.setText(self.Name)

    @property
    def CMD_ARRAY(self):
        self._cmd_array.extend(self.parent.currentSessionID)
        return  self._cmd_array
    def boot(self):
        self.reactor= ProcessThread({'python': self.CMD_ARRAY})
        self.reactor._ProcssOutput.connect(self.LogOutput)
        self.reactor.setObjectName(self.Name)
    def shutdown(self):
        self.ClearRules()
    @property
    def isEnabled(self):
        pass
        
    def Initialize(self):
        pass

    def optionsRules(self,type):
        ''' add rules iptable by type plugins'''
        return self.search[type]

    def SetRules(self,strrules=""):
        items = []
        for index in xrange(self.FSettings.ListRules.count()):
            items.append(str(self.FSettings.ListRules.item(index).text()))
        if self.optionsRules(strrules) in items:
            return
        if (self.optionsRules(strrules) != None):
            item = QtGui.QListWidgetItem()
            item.setText(self.optionsRules(strrules))
            item.setSizeHint(QtCore.QSize(30, 30))
            self.FSettings.ListRules.addItem(item)

    def ClearRules(self):
        for rules in self.search.keys():
            self.unset_Rules(rules)
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
    def Configure(self):
        self.ConfigWindow.show()

    def unset_Rules(self,iptables):
        ''' remove rules from Listwidget in settings widget'''
        items = []
        for index in xrange(self.FSettings.ListRules.count()):
            items.append(str(self.FSettings.ListRules.item(index).text()))
        for position,line in enumerate(items):
            if self.optionsRules(iptables) == line:
                self.FSettings.ListRules.takeItem(position)
    def SaveLog(self):
        pass
    def Serve(self,on=True):
        pass


class Dockable(DockableWidget):
    def __init__(self,parent=0,title="",info={}):
        super(Dockable,self).__init__(parent,title,info)
        self.setObjectName(title)
