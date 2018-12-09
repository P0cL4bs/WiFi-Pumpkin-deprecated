from core.config.globalimport import *
class IP():
    Name="Default"
    ID="Default"
    def __init__(self):
        super(IP,self).__init__()
        self.FSettings= SuperSettings.getInstance()
        self.ClassRanges = ""
        self.DefaultLease = 600
        self.MaxLease = 7200
        self.Subnet = ""
        self.Netmask=""
        self.Router=""
        self.Broadcast=""