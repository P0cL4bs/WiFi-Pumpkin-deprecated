from scapy.all import *
from default import PSniffer
import sys
from io import StringIO

class Hexdump(PSniffer):
    ''' print dump packets http POST  hex '''
    _activated     = False
    _instance      = None
    meta = {
        'Name'      : 'hexdump',
        'Version'   : '1.0',
        'Description' : 'dump packets http POST  hex ',
        'Author'    : 'Pumpkin-Dev',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if Hexdump._instance is None:
            Hexdump._instance = Hexdump()
        return Hexdump._instance

    def filterPackets(self,pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            self.load = pkt[Raw].load
            if self.load.startswith('POST'):
                self.hexdumpPackets(pkt)
                #self.logging.info(self.hexdumpPackets(pkt))
