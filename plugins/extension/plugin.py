import logging
from bs4 import BeautifulSoup
from PyQt4.QtCore import QObject,pyqtSignal
from core.utility.collection import SettingsINI
import core.utility.constants as C

class PluginTemplate(QObject):
	name		= 'plugin master'
	version		= '1.0'
	config		= SettingsINI(C.PUMPPROXY_INI)
	loggers 	= {}
	send_output = pyqtSignal(object)

	def init_logger(self,session):
		self.loggers['Pumpkin-Proxy'] = self.setup_logger('Pumpkin-Proxy',
					'logs/AccessPoint/pumpkin-proxy.log',session)
		self.log = self.loggers['Pumpkin-Proxy']

	def setup_logger(self,logger_name, log_file,key=str(), level=logging.INFO):
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

	def request(self, flow):
		raise NotImplementedError
	def response(self, flow):
		raise NotImplementedError