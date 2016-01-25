from Plugin import PluginProxy

class blurpage(PluginProxy):
    ''' this module proxy set blur into body page html response'''
    _name          = 'blur_page'
    _activated     = False
    _instance      = None
    _requiresArgs  = False

    @staticmethod
    def getInstance():
        if blurpage._instance is None:
            blurpage._instance = blurpage()
        return blurpage._instance

    def __init__(self):
        self.LoggerInjector()
        self.injection_code = []

    def setInjectionCode(self, code):
        self.injection_code.append(code)

    def inject(self, data, url):
        injection_code = '''<head> <style type="text/css">
        body{
		filter: blur(2px);
		-webkit-filter: blur(2px);}
		</style>'''
        self.logging.info("Injected: %s" % (url))
        return data.replace('<head>',injection_code )
