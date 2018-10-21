from core.config.globalimport import *
from collections import OrderedDict
from core.servers.http_handler.proxyhandler import *
from core.widgets.default.uimodel import *
from core.utility.component import ControllerBlueprint


class MitmController(PluginsUI,ControllerBlueprint):
    Name = "MITM"
    Caption = "Activity Monitor"
    mitmhandler = {}
    SetNoMitmMode = QtCore.pyqtSignal(object)
    dockMount = QtCore.pyqtSignal(bool)
    def __init__(self,parent = None,**kwargs):
        super(MitmController, self).__init__(parent)
        self.parent=parent
        self.FSettings = SuperSettings.getInstance()
        #self.uplinkIF = self.parent.Refactor.get_interfaces()
        #self.downlinkIF = self.parent.WLANCard.currentText()
        __manipulator= [prox(parent=self.parent) for prox in MitmMode.MitmMode.__subclasses__()]
        #Keep Proxy in a dictionary
        for k in __manipulator:
            self.mitmhandler[k.Name]=k

        self.m_name = []
        self.m_desc = []
        self.m_settings = []
        for n,p in self.mitmhandler.items():
            self.m_name.append(p.controlui)
            self.m_settings.append(p.btnChangeSettings)
            self.m_desc.append(p.controlui.objectName())
            #self.manipulatorGroup.addButton(p.controlui)
            p.sendSingal_disable.connect(self.DisableMitmMode)
            p.dockwidget.addDock.connect(self.dockUpdate)
            setattr(self,p.ID,p)
            #self.parent.LeftTabBar.addItem(p.tabinterface)
            #self.parent.Stack.addWidget(p)

        self.MitmModeTable = OrderedDict(
            [('Activity Monitor', self.m_name),
             ('Settings', self.m_settings),
             ('Description', self.m_desc)
             ])
        self.table.setColumnCount(3)
        self.table.setRowCount(len(self.MitmModeTable['Activity Monitor']))
        self.table.resizeRowsToContents()
        self.table.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(23)
        self.table.setSortingEnabled(True)
        self.table.setHorizontalHeaderLabels(self.MitmModeTable.keys())
        self.table.horizontalHeader().resizeSection(0, 158)
        self.table.horizontalHeader().resizeSection(1, 80)
        self.table.resizeRowsToContents()

        # add all widgets in Qtable 2 plugin
        Headers = []
        for n, key in enumerate(self.MitmModeTable.keys()):
            Headers.append(key)
            for m, item in enumerate(self.MitmModeTable[key]):
                if type(item) == type(QtGui.QCheckBox()) or type(item) == type(QtGui.QPushButton()):
                    self.table.setCellWidget(m, n, item)
                else:
                    item = QtGui.QTableWidgetItem(item)
                    self.table.setItem(m, n, item)
        self.table.setHorizontalHeaderLabels(self.MitmModeTable.keys())
    def DisableMitmMode(self,status):
        self.SetNoMitmMode.emit(status)
    def dockUpdate(self,add=True):
        self.dockMount.emit(add)
    @property
    def ActiveDock(self):
        manobj = []
        for manip in self.Active:
            manobj.append(manip.dockwidget)
        return manobj
    @property
    def Active(self):
        manobj =[]
        for manip in self.mitmhandler.values():
            if manip.controlui.isChecked():
                manobj.append(manip)
        return manobj
    @property
    def ActiveReactor(self):
        reactor=[]
        for i in self.Active:
            reactor.append(i.reactor)
        return reactor
    @property
    def get(self):
        return self.mitmhandler
    @classmethod
    def disable(cls, val=True):
        pass
    @property
    def disableproxy(self, name):
        pass
    def Start(self):
        for i in self.Active:
            i.boot()
    def Stop(self):
        for i in self.Active:
            i.shutdown()
