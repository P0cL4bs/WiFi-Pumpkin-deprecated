from scapy.all import *
from default import PSniffer

class Kerberos(PSniffer):
    _activated     = False
    _instance      = None
    meta = {
        'Name'      : 'kerberos',
        'Version'   : '1.0',
        'Description' : 'capture The kerberos credentials authentication protocol. ',
        'Author'    : 'DanMcInerney',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if Kerberos._instance is None:
            Kerberos._instance = Kerberos()
        return Kerberos._instance

    def filterPackets(self,pkt):
        if pkt.haslayer(Raw):
            load = pkt[Raw].load

        # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
        if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            return

        # UDP
        if pkt.haslayer(UDP) and pkt.haslayer(IP) and pkt.haslayer(Raw):

            src_ip_port = str(pkt[IP].src) + ':' + str(pkt[UDP].sport)
            dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[UDP].dport)

            # SNMP community strings
            if pkt.haslayer(SNMP):
                self.parse_snmp(src_ip_port, dst_ip_port, pkt[SNMP])
                return

            # Kerberos over UDP
            decoded = self.Decode_Ip_Packet(str(pkt)[14:])
            kerb_hash = self.ParseMSKerbv5UDP(decoded['data'][8:])
            if kerb_hash:
                self.printer(src_ip_port, dst_ip_port, kerb_hash)

        elif pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):

            ack = str(pkt[TCP].ack)
            seq = str(pkt[TCP].seq)
            src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
            dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)

            # Kerberos over TCP
            decoded = self.Decode_Ip_Packet(str(pkt)[14:])
            kerb_hash = self.ParseMSKerbv5TCP(decoded['data'][20:])
            if kerb_hash:
                self.printer(src_ip_port, dst_ip_port, kerb_hash)



    def parse_snmp(self,src_ip_port, dst_ip_port, snmp_layer):
        '''
        Parse out the SNMP version and community string
        '''
        if type(snmp_layer.community.val) == str:
            ver = snmp_layer.version.val
            msg = 'SNMPv%d community string: %s' % (ver, snmp_layer.community.val)
            self.printer(src_ip_port, dst_ip_port, msg)
        return True

    def printer(self,src_ip_port, dst_ip_port, msg):
        print_str = '[%s] %s' % (src_ip_port.split(':')[0], msg)
        self.output.emit({''.format(self.meta.Name): print_str})


    def Decode_Ip_Packet(self,s):
        '''
        Taken from PCredz, solely to get Kerb parsing
        working until I have time to analyze Kerb pkts
        and figure out a simpler way
        Maybe use kerberos python lib
        '''
        d={}
        d['header_len']=ord(s[0]) & 0x0f
        d['data']=s[4*d['header_len']:]
        return d

    def ParseMSKerbv5TCP(self,Data):
        '''
        Taken from Pcredz because I didn't want to spend the time doing this myself
        I should probably figure this out on my own but hey, time isn't free, why reinvent the wheel?
        Maybe replace this eventually with the kerberos python lib
        Parses Kerberosv5 hashes from packets
        '''
        try:
            MsgType = Data[21:22]
            EncType = Data[43:44]
            MessageType = Data[32:33]
        except IndexError:
            return

        if MsgType == "\x0a" and EncType == "\x17" and MessageType == "\x02":
            if Data[49:53] == "\xa2\x36\x04\x34" or Data[49:53] == "\xa2\x35\x04\x33":
                HashLen = struct.unpack('<b', Data[50:51])[0]
                if HashLen == 54:
                    Hash = Data[53:105]
                    SwitchHash = Hash[16:] + Hash[0:16]
                    NameLen = struct.unpack('<b', Data[153:154])[0]
                    Name = Data[154:154 + NameLen]
                    DomainLen = struct.unpack('<b', Data[154 + NameLen + 3:154 + NameLen + 4])[0]
                    Domain = Data[154 + NameLen + 4:154 + NameLen + 4 + DomainLen]
                    BuildHash = "$krb5pa$23$" + Name + "$" + Domain + "$dummy$" + SwitchHash.encode('hex')
                    return 'MS Kerberos: %s' % BuildHash

            if Data[44:48] == "\xa2\x36\x04\x34" or Data[44:48] == "\xa2\x35\x04\x33":
                HashLen = struct.unpack('<b', Data[47:48])[0]
                Hash = Data[48:48 + HashLen]
                SwitchHash = Hash[16:] + Hash[0:16]
                NameLen = struct.unpack('<b', Data[HashLen + 96:HashLen + 96 + 1])[0]
                Name = Data[HashLen + 97:HashLen + 97 + NameLen]
                DomainLen = struct.unpack('<b', Data[HashLen + 97 + NameLen + 3:HashLen + 97 + NameLen + 4])[0]
                Domain = Data[HashLen + 97 + NameLen + 4:HashLen + 97 + NameLen + 4 + DomainLen]
                BuildHash = "$krb5pa$23$" + Name + "$" + Domain + "$dummy$" + SwitchHash.encode('hex')
                return 'MS Kerberos: %s' % BuildHash

            else:
                Hash = Data[48:100]
                SwitchHash = Hash[16:] + Hash[0:16]
                NameLen = struct.unpack('<b', Data[148:149])[0]
                Name = Data[149:149 + NameLen]
                DomainLen = struct.unpack('<b', Data[149 + NameLen + 3:149 + NameLen + 4])[0]
                Domain = Data[149 + NameLen + 4:149 + NameLen + 4 + DomainLen]
                BuildHash = "$krb5pa$23$" + Name + "$" + Domain + "$dummy$" + SwitchHash.encode('hex')
                return 'MS Kerberos: %s' % BuildHash



    def ParseMSKerbv5UDP(self,Data):
        '''
        Taken from Pcredz because I didn't want to spend the time doing this myself
        I should probably figure this out on my own but hey, time isn't free why reinvent the wheel?
        Maybe replace this eventually with the kerberos python lib
        Parses Kerberosv5 hashes from packets
        '''

        try:
            MsgType = Data[17:18]
            EncType = Data[39:40]
        except IndexError:
            return

        if MsgType == "\x0a" and EncType == "\x17":
            try:
                if Data[40:44] == "\xa2\x36\x04\x34" or Data[40:44] == "\xa2\x35\x04\x33":
                    HashLen = struct.unpack('<b',Data[41:42])[0]
                    if HashLen == 54:
                        Hash = Data[44:96]
                        SwitchHash = Hash[16:]+Hash[0:16]
                        NameLen = struct.unpack('<b',Data[144:145])[0]
                        Name = Data[145:145+NameLen]
                        DomainLen = struct.unpack('<b',Data[145+NameLen+3:145+NameLen+4])[0]
                        Domain = Data[145+NameLen+4:145+NameLen+4+DomainLen]
                        BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                        return 'MS Kerberos: %s' % BuildHash

                    if HashLen == 53:
                        Hash = Data[44:95]
                        SwitchHash = Hash[16:]+Hash[0:16]
                        NameLen = struct.unpack('<b',Data[143:144])[0]
                        Name = Data[144:144+NameLen]
                        DomainLen = struct.unpack('<b',Data[144+NameLen+3:144+NameLen+4])[0]
                        Domain = Data[144+NameLen+4:144+NameLen+4+DomainLen]
                        BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                        return 'MS Kerberos: %s' % BuildHash

                else:
                    HashLen = struct.unpack('<b',Data[48:49])[0]
                    Hash = Data[49:49+HashLen]
                    SwitchHash = Hash[16:]+Hash[0:16]
                    NameLen = struct.unpack('<b',Data[HashLen+97:HashLen+97+1])[0]
                    Name = Data[HashLen+98:HashLen+98+NameLen]
                    DomainLen = struct.unpack('<b',Data[HashLen+98+NameLen+3:HashLen+98+NameLen+4])[0]
                    Domain = Data[HashLen+98+NameLen+4:HashLen+98+NameLen+4+DomainLen]
                    BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                    return 'MS Kerberos: %s' % BuildHash
            except struct.error:
                return