from Plugin import PluginProxy

class background(PluginProxy):
    ''' this module proxy add image background on html page.'''
    _name          = 'background'
    _argsname      = 'Url:'
    _activated     = False
    _instance      = None
    _requiresArgs  = True

    @staticmethod
    def getInstance():
        if background._instance is None:
            background._instance = background()
        return background._instance

    def __init__(self):
        self.LoggerInjector()
        self.url_image = None

    def setInjectionCode(self, code):
        self.url_image = code

    def inject(self, data, url):
        injection_code = '''<style>
        body  {
        background-image: url("%s");
        }
        </style>
        </head>'''%(self.url_image)
        self.logging.info("Injected: %s" % (url))
        return data.replace('</head>',injection_code)
