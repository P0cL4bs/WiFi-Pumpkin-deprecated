import logging
from Core.Utils import setup_logger

class PluginProxy(object):
    '''' Main class Modules '''

    def inject(self, data, url):
        ''' called injection data on responseTamperer'''
        raise NotImplementedError

    def setInjectionCode(self, code):
        ''' function set content data to injection'''
        raise NotImplementedError

    def LoggerInjector(self):
        setup_logger('injectionPage',
        './Logs/AccessPoint/injectionPage.log')
        self.logging = logging.getLogger('injectionPage')