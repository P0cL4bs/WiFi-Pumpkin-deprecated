from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.Qt import *

from core.widgets.docks.dock import DockableWidget
from core.widgets.default.uimodel import CoreSettings

class ActivityMonitor(DockableWidget):
    id = "Default"
    title="Default"
    def __init__(self,parent = None, title="Default",info={}):
        super(ActivityMonitor,self).__init__(parent,title)
        self.setObjectName(title)
        self.settings = ActivityMonitorSettings(self.parent)
        self.maindockwidget = QGroupBox()
        self.maindockwidget.setLayout(self.mainlayout)