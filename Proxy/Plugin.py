import logging
from Core.Utils import setup_logger

class PluginProxy(object):
    '''' Main class Modules '''

    def inject(self, data, url):
        pass

    def setInjectionCode(self, code):
        pass

    def LoggerInjector(self):
        setup_logger('injectionPage',
        './Logs/AccessPoint/injectionPage.log')
        self.logging = logging.getLogger('injectionPage')