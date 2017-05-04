from re import findall
import logging
from sys import stdout
from scapy.all import hexdump
from core.utility.collection import SettingsINI
from PyQt4.QtCore import pyqtSignal

class PSniffer(object):
    ''' plugins data sniffers'''
    name    = 'plugin TCP proxy master'
    version = '1.0'
    config  = SettingsINI('core/config/app/proxy.ini')
    loggers = {}
    output  = pyqtSignal(object)
    session = None

    def filterPackets(self,pkt):
        ''' intercept packetes data '''
        raise NotImplementedError

    def get_http_headers(self,http_payload):
        ''' get header dict http request'''
        try:
            headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
            headers = dict(findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
        except:
            return None
        if 'Content-Type' not in headers:
            return None

        return headers

    def setup_logger(self, logger_name, log_file, key=str(), level=logging.INFO):
        if self.loggers.get(logger_name):
            return self.loggers.get(logger_name)
        else:
            logger = logging.getLogger(logger_name)
            formatter = logging.Formatter('SessionID[{}] %(asctime)s : %(message)s'.format(key))
            fileHandler = logging.FileHandler(log_file, mode='a')
            fileHandler.setFormatter(formatter)
            logger.setLevel(logging.INFO)
            logger.addHandler(fileHandler)
        return logger

    def hexdumpPackets(self,pkt):
        ''' show packets hexdump '''
        return hexdump(pkt)