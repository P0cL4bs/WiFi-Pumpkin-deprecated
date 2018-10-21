from PyQt4 import QtCore, QtGui
import core.utility.constants as C
from core.main import version
from core.utility.settings import frm_Settings as SuperSettings

class ApplicationLoop(QtGui.QApplication):

    def __init__(self, argv):
        QtGui.QApplication.__init__(self, argv)
        self._memory    = QtCore.QSharedMemory(self)
        self.key        = 'WiFi-Pumpkin'
        self._memory.setKey(self.key)
        self.setApplicationName(self.key)
        self.setApplicationVersion(version)
        self.setOrganizationName('P0cL4bs Team')
        self.setWindowIcon(QtGui.QIcon('icons/icon.ico'))
        self.setAppQTDesigner(self.style().objectName())
        self.Settings = SuperSettings()
        self.Settings.hide()
        if self._memory.attach():
            self._running = True
        else:
            self._running = False
            if not self._memory.create(1):
                raise RuntimeError(self._memory.errorString())


    def setAppQTDesigner(self,style):
        if 'gtk+' in str(style).lower():
            self.setStyle(QtGui.QStyleFactory.create(C.GTKTHEME))


    def isRunning(self):
        return self._running