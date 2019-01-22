from core.config.globalimport import *
from collections import OrderedDict
from core.widgets.default.uimodel import *
from core.servers.proxy.package import *
from core.utility.component import ControllerBlueprint
from core.utility.threads import ThreadPumpkinProxy



class ProxyModeController(PluginsUI,ControllerBlueprint):
    Name = "Proxy"
    Caption = "Enable Proxy Server"
    proxies = {}
    SetNoProxy = QtCore.pyqtSignal(object)
    dockMount = QtCore.pyqtSignal(bool)

    def __init__(self,parent = None,**kwargs):
        super(ProxyModeController, self).__init__(parent)
        self.parent=parent
        self.FSettings = SuperSettings.getInstance()
        self.setCheckable(True)
        self.setChecked(self.FSettings.Settings.get_setting('plugins', 'disableproxy', format=bool))
        self.clicked.connect(self.get_disable_proxy)
        self.proxyGroup = QtGui.QButtonGroup()
        __proxlist= [prox(parent=self.parent) for prox in ProxyMode.ProxyMode.__subclasses__()]

        #Keep Proxy in a dictionary
        for k in __proxlist:
            self.proxies[k.Name]=k

        self.p_name = []
        self.p_desc = []
        self.p_settings = []
        self.p_author = []
        self.NoProxy = None
        for n,p in self.proxies.items():
            if p.Name == "No Proxy":
                self.NoProxy = p
            self.p_name.append(p.controlui)
            self.p_settings.append(p.btnChangeSettings)
            self.p_author.append(p.Author)
            self.p_desc.append(p.controlui.objectName())
            if (type(p.controlui) == type(QtGui.QRadioButton()) ):
                self.proxyGroup.addButton(p.controlui)
            p.sendSingal_disable.connect(self.DisableProxy)
            p.dockwidget.addDock.connect(self.dockUpdate)
            if (hasattr(p,'ID')):
                setattr(self.parent, p.ID, p)

        self.THeadersPluginsProxy = OrderedDict(
            [('Proxies', self.p_name),
             ('Settings', self.p_settings),
             ('Author', self.p_author),
             ('Description', self.p_desc)
             ])
            
        
        
        self.table.setColumnCount(4)
        self.table.setRowCount(len(self.proxies))
        self.table.resizeRowsToContents()
        self.table.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(23)
        self.table.setSortingEnabled(True)
        self.table.setHorizontalHeaderLabels(self.THeadersPluginsProxy.keys())
        self.table.horizontalHeader().resizeSection(0, 158)
        self.table.horizontalHeader().resizeSection(1, 80)
        self.table.resizeRowsToContents()
        # add all widgets in Qtable 1 plgins
        Headers = []
        for n, key in enumerate(self.THeadersPluginsProxy.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeadersPluginsProxy[key]):
                if type(item) == type(QtGui.QRadioButton()) or type(item) == type(QtGui.QPushButton()):
                    self.table.setCellWidget(m, n, item)
                elif type(item) == type(QtGui.QCheckBox()):
                    self.table.setCellWidget(m, n, item)
                else:
                    item = QtGui.QTableWidgetItem(item)
                    self.table.setItem(m, n, item)
        self.table.setHorizontalHeaderLabels(self.THeadersPluginsProxy.keys())
        
        
        # change default pyoxy to DNS2Proxy if mitmproxy is not installed
        if not ThreadPumpkinProxy.isMitmProxyInstalled() and self.Active.Name == 'Pumpkin Proxy':
            for p_controlui in self.p_name:
                if (p_controlui.text() == 'SSLStrip+DNS2Proxy'):
                    p_controlui.setChecked(True)
                    break
        
    def get_disable_proxy(self):


        if self.isChecked():
            if self.Active.Name == "No Proxy":
                self.SetNoProxy.emit(False)
            else:

                self.parent.set_proxy_statusbar(self.Active.Name, disabled=False)
                self.FSettings.Settings.set_setting('plugins', 'disableproxy',
                                                    self.isChecked())

        else:
            self.SetNoProxy.emit(self.isChecked())
            self.FSettings.Settings.set_setting('plugins', 'disableproxy',
                                                self.isChecked())


    def dockUpdate(self,add=True):
        self.dockMount.emit(add)
    def DisableProxy(self,status):
        self.SetNoProxy.emit(status)
    @property
    def ActiveDocks(self):
        return self.Active.dockwidget

    @property
    def ActiveReactor(self):
        reactor = []
        if self.isChecked():

            for act in self.proxies.values():
                if act.controlui.isChecked():
                    if act.Name == "No Proxy":
                        reactor.append(act.reactor)
                        reactor.append(act.subreactor)
                    else:
                        reactor.append(act.reactor)
                        if act.subreactor:
                            reactor.append(act.subreactor)
        else:
            reactor.append(self.NoProxy.reactor)
            reactor.append(self.NoProxy.subreactor)
        return  reactor



    @property
    def Active(self):
        if self.isChecked():

            for act in self.proxies.values():
                # exclude tcp proxy log
                if act.controlui.text() != 'TCP Proxy':
                    if act.controlui.isChecked():
                        if act.Name == "No Proxy":
                            return self.NoProxy
                        else:
                            return act
        else:
            return self.NoProxy

    @property
    def ActiveLoad(self):
        ''' load all proxies type checkbox UI in tab plugins '''
        proxies = []
        if self.isChecked():
            for act in self.proxies.values():
                if act.controlui.isChecked():
                    if act.Name != "No Proxy":
                        proxies.append(act)
        return  proxies

    @property
    def get(self):
        return self.proxies
    @classmethod
    def disable(cls, val=True):
        pass
    @property
    def disableproxy(self, name):
        pass
    def Start(self):
        self.setEnabled(False)
        self.Active.Initialize()
        self.Active.Serve()
        self.Active.boot()
        # load proxy checkbox all type all proxies
        for proxy in self.ActiveLoad:
            if (proxy.Name != self.Active.Name):
                proxy.Initialize()
                proxy.Serve()
                proxy.boot()

    def Stop(self):
        self.setEnabled(True)
        self.Active.Serve(False)
        self.Active.shutdown()
    def SaveLog(self):

        self.Active.SaveLog()
