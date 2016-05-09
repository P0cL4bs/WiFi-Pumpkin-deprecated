from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.Utils import Refactor,set_monitor_mode
from subprocess import Popen,PIPE
from Core.utility.settings import frm_Settings
from Modules.servers.PhishingManager import frm_PhishingManager
from Core.utility.threads import ThreadPopen,ThreadScan,ProcessThread
from Core.packets.network import ThARP_posion,ThSpoofAttack
class PumpkinModule(QWidget):
    ''' this is Qwidget Module base '''
    def __init__(self,parent=None,*args):
        super(PumpkinModule, self).__init__(parent)
        self.setWindowIcon(QIcon('Icons/icon.ico'))
        self.module_network = Refactor
        self.configure      = frm_Settings()
        self.Ftemplates     = frm_PhishingManager()
        self.interfaces     = Refactor.get_interfaces()
    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())