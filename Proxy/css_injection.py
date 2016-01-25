from Plugin import PluginProxy

class InjectorCSS(PluginProxy):
    """  inject CSS files inside HTML pages """
    _name          = 'inject_css'
    _argsname      = 'FilePath:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True

    @staticmethod
    def getInstance():
        if InjectorCSS._instance is None:
            InjectorCSS._instance = InjectorCSS()

        return InjectorCSS._instance

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
            return data.replace('</body>', '<script>%s</script></body>' % injection_code)
        else:
            return data
