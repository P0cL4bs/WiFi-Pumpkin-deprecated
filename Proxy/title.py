from Plugin import PluginProxy

class title(PluginProxy):
    ''' this module proxy add title on html page.'''
    _name          = 'title_change'
    _argsname      = 'Title:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True

    @staticmethod
    def getInstance():
        if title._instance is None:
            title._instance = title()
        return title._instance

    def __init__(self):
        self.LoggerInjector()
        self.title = None

    def setInjectionCode(self, code):
        self.title = code

    def inject(self, data, url):
        injection_code = '<title> {} '.format(self.title)
        self.logging.info("Injected: %s" % (url))
        return data.replace('<title>',injection_code)
