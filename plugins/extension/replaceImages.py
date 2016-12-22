import cStringIO
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

class replaceImages(PluginTemplate):
    meta = {
        'Name'      : 'replaceImages',
        'Version'   : '1.0',
        'Description' : 'this module proxy replace all images with the picture .',
        'Author'    : 'Marcos Nesster'
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value
        self.ConfigParser = True
        self.imagePath = self.config.get_setting('set_replaceImages','path')

    def request(self, flow):
        pass

    def response(self,flow):
        if str(flow.response.headers['Content-Type']).startswith('image'):
            if path.isfile(self.imagePath):
                with decoded(flow.response):
                    try:
                        img = cStringIO.StringIO(open(self.imagePath, 'rb').read())
                        flow.response.content = img.getvalue()
                        self.send_output.emit('[{}] URL:{} image replaced...'.format(self.Name,flow.request.url))
                    except:
                        pass