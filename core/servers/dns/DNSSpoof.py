from core.config.globalimport import *
from core.utility.threads import ProcessThread
from core.servers.dns.DNSBase import DNSBase
from core.servers.dhcp.dhcpserver import  DNSServer

class DNSSpoof(DNSBase):
    ID = "DNSSpoof"
    Name = "DNSSpoof Server"
    ExecutableFile = "dnsspoofer"
    def __init__(self,parent):
        super(DNSSpoof,self).__init__(parent)
        if self.command is None:
            self.controlui.setText("{} not Found".format(self.Name))
            self.controlui.setDisabled(True)

    @property
    def commandargs(self):
        cmd=[]
        cmd.extend(['-i',str(self.SessionConfig.DHCP.router.text()),'-p', '53'])
        return cmd
