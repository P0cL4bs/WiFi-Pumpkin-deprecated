from core.utility.threads import  (
    ProcessThread
)
from core.widgets.docks.dock import DockableWidget
from core.controllers.wirelessmodecontroller import AccessPointSettings
from core.widgets.default.uimodel import *
class Widget(QtGui.QFrame):
    def __init__(self,parent):
        QtGui.QWidget.__init__(self,parent)
class VBox(QtGui.QVBoxLayout):
    def __init__(self):
        QtGui.QVBoxLayout.__init__(self)
class MitmDock(DockableWidget):
    id = "Generic"
    title = "Generic"

    def __init__(self,parent=0,title="",info={}):
        super(MitmDock,self).__init__(parent,title,info)
        self.setObjectName(self.title)


class MitmMode(Widget):
    Name = "Generic"
    ID = "Generic"
    Author = "Wahyudin Aziz"
    Description = "Generic Placeholder for Attack Scenario"
    Icon = "icons/plugins-new.png"
    LogFile = C.LOG_ALL
    ModSettings = False
    ModType = "proxy" # proxy or server
    Hidden = True
    _cmd_array = []
    plugins = []
    sendError = QtCore.pyqtSignal(str)
    sendSingal_disable = QtCore.pyqtSignal(object)

    def __init__(self,parent=None):
        super(MitmMode, self).__init__(parent)
        self.parent = parent
        self.FSettings = SuperSettings.getInstance()
        self.reactor = None
        self.server = None
        setup_logger(self.Name, self.LogFile, self.parent.currentSessionID)
        self.logger = getLogger(self.Name)
        self.popup = QtGui.QWidget()
        self.tabinterface = QtGui.QListWidgetItem()
        self.tabinterface.setText(self.Name)
        self.tabinterface.setSizeHint(QtCore.QSize(30, 30))
        self.tabinterface.setIcon(QtGui.QIcon(self.Icon))
        self.ConfigWindow = OptionDialog(self)
        self.ConfigWindow.setWindowTitle("{} Settings".format(self.Name))

        self.controlui = QtGui.QCheckBox(self.Name)
        self.controlui.setObjectName(QtCore.QString(self.Description))
        self.controlui.setChecked(self.FSettings.Settings.get_setting('mitmhandler', self.Name, format=bool))
        self.controlui.toggled.connect(self.CheckOptions)

        self.setEnabled(self.FSettings.Settings.get_setting('mitmhandler', self.Name, format=bool))
        self.btnChangeSettings = QtGui.QPushButton("None")
        self.btnChangeSettings.setEnabled(False)

        if self.ModSettings:
            self.btnChangeSettings.setEnabled(self.controlui.isChecked())
            self.btnChangeSettings.setText("Change")
            self.btnChangeSettings.setIcon(QtGui.QIcon('icons/config.png'))
            self.btnChangeSettings.clicked.connect(self.Configure)

        self.dockwidget = MitmDock(None,title=self.Name)
        self.dockwidget.addDock.emit(self.controlui.isChecked())
        self.mainLayout = QtGui.QFormLayout()
        self.scrollwidget = QtGui.QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QtGui.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)
        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(self.scroll)
    @property
    def CMD_ARRAY(self):
        return self._cmd_array

    @property
    def Wireless(self):
        return AccessPointSettings.instances[0]
    @property
    def hasSettings(self):
        return self.ModSettings
    def CheckOptions(self):
        self.FSettings.Settings.set_setting('mitmhandler', self.Name, self.controlui.isChecked())
        self.dockwidget.addDock.emit(self.controlui.isChecked())
        if self.ModSettings:
            self.btnChangeSettings.setEnabled(self.controlui.isChecked())
        if self.controlui.isChecked() == True:
            self.setEnabled(True)
        else:
            self.setEnabled(False)
        self.Initialize()
    def Initialize(self):
        self.SetRules()
    def SetRules(self):
        pass
    def ClearRules(self):
        pass
    def Configure(self):
        self.ConfigWindow.show()
    def boot(self):
        if self.CMD_ARRAY:
            self.reactor= ProcessThread({'python': self.CMD_ARRAY})
            self.reactor._ProcssOutput.connect(self.LogOutput)
            self.reactor.setObjectName(self.Name)
    def shutdown(self):
        if self.reactor is not None:
            self.reactor.stop()
            if hasattr(self.reactor, 'wait'):
                if not self.reactor.wait(msecs=500):
                    self.reactor.terminate()
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




