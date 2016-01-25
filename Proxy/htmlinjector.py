from Plugin import PluginProxy

class HTMLInjector(PluginProxy):
    """ This plugins allows you to inject data into the response returned from the web server.
    """
    _name          = 'html_injector'
    _argsname      = 'FilePath:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True

    @staticmethod
    def getInstance():
        if HTMLInjector._instance is None:
            HTMLInjector._instance = HTMLInjector()

        return HTMLInjector._instance

    def __init__(self):
        self.LoggerInjector()
        self.injection_code = []

    def setInjectionCode(self, code):
        with open(code,'r') as f:
            self.injection_code.append(f.read())

    def inject(self, data, url):
        injection_code = ' '.join(self.injection_code)
        if (injection_code != ""):
            self.logging.info("Injected: %s" % (url))
            return data.replace('</body>', '%s</body>' % injection_code)
        else:
            return data
