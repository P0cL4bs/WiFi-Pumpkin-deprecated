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

class shakepage(PluginTemplate):
    meta = {
        'Name'      : 'shakepage',
        'Version'   : '1.0',
        'Description' : 'this plugin proxy added javascript to shake page',
        'Author'    : 'Marcos Nesster'
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.ConfigParser = False

    def request(self, flow):
        pass

    def response(self, flow):
        with decoded(flow.response):
            if flow.response.content:
                c = flow.response.content.replace('</body>', '''<script>
                window.onload=function() {
                    var move=document.getElementsByTagName("body")[0];
                    setInterval(function() {
                        move.style.marginTop=(move.style.marginTop=="4px")?"-4px":"4px";
                    }, 5);
                }
                </script></body>''')
                if c > 0:
                    self.send_output.emit('[{}] {} javascript injected...'.format(self.Name,flow.request.pretty_host))