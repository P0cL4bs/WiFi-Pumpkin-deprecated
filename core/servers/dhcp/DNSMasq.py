from core.config.globalimport import *
from core.utility.threads import ThRunDhcp
from core.servers.dhcp.dhcp import DHCPServers

class DNSMasqDhcp(DHCPServers):
    Name = "DNSMasq DHCP Server"
    ID = "DNSMASQ"
    ExecutableFile = "dnsmasq"
    def __init__(self,parent=0):
        super(DNSMasqDhcp,self).__init__(parent)
        if self.command is None:
            self.controlui.setText("{} not Found".format(self.Name))
            self.controlui.setDisabled(True)

    def Initialize(self):
        leases = C.DHCPLEASES_PATH
        if not os.path.exists(leases[:-12]):
            os.mkdir(leases[:-12])
        if not os.path.isfile(leases):
            with open(leases, 'wb') as leaconf:
                leaconf.close()
        uid = getpwnam('root').pw_uid
        gid = getgrnam('root').gr_gid
        os.chown(leases, uid, gid)
        
    