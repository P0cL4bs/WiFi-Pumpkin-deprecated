from scapy.all import *
from default import PSniffer
from dns import resolver

class Summary(PSniffer):
    _activated     = False
    _instance      = None
    meta = {
        'Name'      : 'summary',
        'Version'   : '1.0',
        'Description' : 'quick look at the packet is layers: ',
        'Author'    : 'Pumpkin-Dev',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if Summary._instance is None:
            Summary._instance = Summary()
        return Summary._instance

    def filterPackets(self,pkt):
        if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            return
        #if pkt.haslayer(DNSQR):
        #    print ('{} ->() has searched for: {}'.format(pkt[IP].src, pkt[DNS].qd.qname[:len(str(pkt[DNS].qd.qname)) - 1]))
        #return self.output.emit({'{}'.format(self.meta['Name']): "Packet : %s ==> %s" % (pkt[0][1].src, pkt[0][1].dst)})
