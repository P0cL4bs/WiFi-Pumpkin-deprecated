from core.config.globalimport import *
from core.utility.component import ControllerBlueprint
from core.servers.dhcp import *

class DHCPController(ControllerBlueprint):
    def __init__(self,parent):
        super(DHCPController,self).__init__()
        self.parent = parent
        __dhcpmode = dhcp.DHCPSettings.instances[0].dhmode
        self.mode = {}
        for k in __dhcpmode:
            self.mode[k.ID]=k
    def Start(self):
        self.Active.Start()
    @property
    def ActiveService(self):
        return self.Active.service
    @property
    def Active(self):
        for i in self.mode.values():
            if i.controlui.isChecked():
                return i
    @property
    def ActiveReactor(self):
        #reactor=[self.Active.reactor,self.Active.service]
        return self.Active.reactor
    def Stop(self):
        self.Active.Stop()

