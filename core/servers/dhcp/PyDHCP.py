from core.config.globalimport import *
from core.servers.dhcp.dhcpserver import DHCPServer, DNSServer
from core.utility.threads import ProcessThread
from core.servers.dhcp.dhcp import DHCPServers

class PyDHCP(DHCPServers):
    Name = "Python DHCP Server"
    ID = "PyDHCP"
    def __init__(self,parent=0):
        super(PyDHCP,self).__init__(parent)
        self._isRunning = False
    def Initialize(self):
        pass

    def setIsRunning(self,value):
        self._isRunning = value

    @property
    def getStatusReactor(self):
        return self._isRunning

    def boot(self):
        self.reactor = DHCPServer(str(self.parent.SessionConfig.Wireless.WLANCard.currentText()), self.parent.SessionConfig.DHCP.conf)
        if not self.getStatusReactor:
            self.setIsRunning(True)
            self.reactor.sendConnetedClient.connect(self.get_DHCP_Discover_clients)
            self.reactor.setObjectName('Py_DHCP')
        self.reactor.LoopDhcpStatus = True