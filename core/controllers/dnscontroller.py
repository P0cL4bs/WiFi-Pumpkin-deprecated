from core.config.globalimport import *
from core.utility.component import ControllerBlueprint
from core.servers.dns import *


class DNSController(QtGui.QGroupBox,ControllerBlueprint):
    dockMount = QtCore.pyqtSignal(bool)
    def __init__(self,parent=None,**kwargs):
        super(DNSController,self).__init__(parent)
        self.parent = parent
        self.DNSSettings = DNSBase.DNSSettings.getInstance()
        for dns in self.DNSSettings.dnslist:
            dns.dockwidget.addDock.connect(self.dockUpdate)
            setattr(self,dns.ID,dns)
    def dockUpdate(self,add=True):
        self.dockMount.emit(add)
    def Start(self):
        self.Active.Start()
    @property
    def ActiveReactor(self):
        return self.Active.reactor
    @property
    def Active(self):
        for dns in self.DNSSettings.dnslist:
            if dns.controlui.isChecked():
                return dns



