from core.config.globalimport import *
from core.utility.threads import ProcessThread
from core.servers.dns.DNSBase import DNSBase
from core.servers.dhcp.dhcpserver import  DNSServer

class DNSChef(DNSBase):
    ID = "DNSChef"
    Name = "DNSChef Server"
    ExecutableFile = "dnschef"
    def __init__(self,parent):
        super(DNSChef,self).__init__(parent)
    @property
    def commandargs(self):
        cmd=[]
        cmd.extend(['-i',str(self.SessionConfig.DHCP.router.text()),'-p', '53'])
        return cmd
