from core.main import  QtGui,QtCore
from core.utils import Refactor,set_monitor_mode
from subprocess import Popen,PIPE
from core.utility.collection import SettingsINI
from core.utility.settings import frm_Settings
from modules.servers.PhishingManager import frm_PhishingManager
from core.utility.threads import ThreadPopen,ThreadScan,ProcessThread,ThreadFastScanIP
from core.packets.network import ThARP_posion,ThSpoofAttack
import core.utility.constants as C

"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    default widgets.

Copyright:
    Copyright (C) 2015-2017 Marcos Nesster P0cl4bs Team
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

class PumpkinModule(QtGui.QWidget):
    ''' this is Qwidget Module base '''
    def __init__(self,parent=None,*args):
        super(PumpkinModule, self).__init__(parent)
        self.setWindowIcon(QtGui.QIcon('icons/icon.ico'))
        self.module_network = Refactor
        self.configure      = frm_Settings.instances[0]
        self.Ftemplates     = frm_PhishingManager()
        self.interfaces     = Refactor.get_interfaces()
        self.loadtheme(self.configure.get_theme_qss())

    def loadtheme(self,theme):
        sshFile=("core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QtGui.QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())