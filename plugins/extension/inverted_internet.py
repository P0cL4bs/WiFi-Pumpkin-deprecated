from mitmproxy.models import decoded
from plugins.extension.plugin import PluginTemplate

class inverted_internet(PluginTemplate):
    meta = {
        'Name'      : 'inverted_internet',
        'Version'   : '1.0',
        'Description' : 'add style html for inverte body content.',
        'Author'    : 'David @davoclavo'
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
                c = flow.response.content.replace('</body>', '<style>body '
                '{transform:rotate(180deg);-ms-transform:rotate(180deg);-webkit-transform:rotate(180deg);}'
                '</style></body>')
                if c > 0:
                    self.send_output.emit('[{}] {} CSS injected...'.format(self.Name,flow.request.pretty_host))