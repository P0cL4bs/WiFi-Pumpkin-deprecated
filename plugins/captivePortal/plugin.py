import logging
from core.utility.collection import SettingsINI
import core.utility.constants as C



"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    plugins for CaptivePortal-Proxy.

Copyright:
    Copyright (C) 2015-2016 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

class CaptiveTemplatePlugin(object):
	Name		= 'plugin template captive-portal'
	version		= '1.0'
	config		= SettingsINI(C.CAPTIVEPORTAL_INI)
	loggers 	= {}

	def init_logger(self,session):
		self.loggers['CaptivePortal'] = self.setup_logger('CaptivePortal',
					'logs/AccessPoint/captive-portal.log',session)
		self.log = self.loggers['CaptivePortal']

	def init_language(self, lang):
		pass

	def getSellectedLanguage(self):
		selected_lang,key = None,'set_{}'.format(self.Name)
		for lang in self.config.get_all_childname(key):
			if (self.config.get_setting(key,lang, format=bool)):
				selected_lang = lang
		return selected_lang
	
	def initialize(self):
		self.init_language(self.getSellectedLanguage())

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