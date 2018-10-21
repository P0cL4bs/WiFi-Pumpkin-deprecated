from core.utility.ipclass import *

class ClassA(IP):
    Name = "Class A"
    ID = "ClassA"
    def __init__(self):
        super(ClassA,self).__init__()
        self.ClassRanges="10.0.0.20/10.0.0.50"
        self.Netmask="255.0.0.0"
        self.Broadcast="10.0.0.255"
        self.Router="10.0.0.1"
        self.Subnet="10.0.0.0"