from core.config.globalimport import *
from os import *
from core.utility.threads import ThRunDhcp
from core.servers.dhcp.dhcp import DHCPServers

class ISCDHCP(DHCPServers):
    Name = "ISC DHCP Server"
    ID = "ISCDHCP"
    ExecutableFile = "dhcpd"
    def __init__(self,parent=0):
        super(ISCDHCP,self).__init__(parent)
        self.service = None
        if self.command is None:
            self.controlui.setText("{} not Found".format(self.Name))
            self.controlui.setDisabled(True)

    def Initialize(self):
        leases = C.DHCPLEASES_PATH
        if not path.exists(leases[:-12]):
            mkdir(leases[:-12])
        if not path.isfile(leases):
            with open(leases, 'wb') as leaconf:
                leaconf.close()
        uid = getpwnam('root').pw_uid
        gid = getgrnam('root').gr_gid
        chown(leases, uid, gid)

    def boot(self):
        self.reactor = ThRunDhcp(['dhcpd', '-d', '-f', '-lf', C.DHCPLEASES_PATH, '-cf',
                                      '/etc/dhcp/dhcpd.conf', self.parent.SettingsEnable['AP_iface']],
                                     self.parent.currentSessionID)
        self.reactor.sendRequest.connect(self.get_DHCP_Requests_clients)
        self.reactor.setObjectName('ISC_DHCP')
        
    