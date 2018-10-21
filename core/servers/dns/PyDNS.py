from core.config.globalimport import *
from core.utility.threads import ProcessThread
from core.servers.dns.DNSBase import DNSBase
from core.servers.dhcp.dhcpserver import  DNSServer

class PyDNSServer(DNSBase):
    ID = "PyDNS"
    Name = "PyDNS Server"
    ExecutableFile = ""
    def __init__(self,parent):
        super(PyDNSServer,self).__init__(parent)
    @property
    def commandargs(self):
        pass

    def boot(self):
        self.reactor = DNSServer(str(self.SessionConfig.Wireless.WLANCard.currentText()),
                                             self.SessionConfig.DHCP.conf['router'])
        self.reactor.setObjectName(self.Name)  # use dns2proxy as DNS server
