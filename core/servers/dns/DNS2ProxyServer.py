from core.config.globalimport import *
from core.utility.threads import ProcessThread
from core.servers.dns.DNSBase import DNSBase

class DNS2ProxyServer(DNSBase):
    ID = "DNS2Proxy"
    Name = "DNS2Proxy Server"
    ExecutableFile = "plugins/external/dns2proxy/dns2proxy.py"
    def __init__(self,parent):
        super(DNS2ProxyServer,self).__init__(parent)
    @property
    def commandargs(self):
        cmd=[]
        cmd.insert(0,self.ExecutableFile)
        cmd.extend(['-i',str(self.parent.SessionConfig.Wireless.WLANCard.currentText()),'-k', self.parent.currentSessionID])
        return cmd
    def boot(self):
        self.reactor = ProcessThread({'python': self.commandargs})
        #self.reactor._ProcssOutput.connect(self.parent.get_dns2proxy_output)
        self.reactor._ProcssOutput.connect(self.LogOutput)
        self.reactor.setObjectName(self.Name)  # use dns2proxy as DNS server
