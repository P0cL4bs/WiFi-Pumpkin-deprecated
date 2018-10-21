from core.servers.http_handler.proxyhandler.MitmMode import MitmMode
import core.utility.constants as C
from collections import OrderedDict
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.Qt import *

from core.widgets.docks.dock import DockableWidget
class URLMonitorDock(DockableWidget):
    id = "URLMonitor"
    title = "URLMonitor"
    def __init__(self,parent=None,title="",info={}):
        super(URLMonitorDock,self).__init__(parent,title,info)
        self.maindockwidget = QTreeView()
        self.maindockwidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['URL', 'HTTP-Headers'])
        self.maindockwidget.setModel(self.model)
        self.maindockwidget.setUniformRowHeights(True)
        self.maindockwidget.setColumnWidth(0, 130)
        self.setWidget(self.maindockwidget)
        self.setObjectName(self.title)

    def writeModeData(self, data):
        ''' get data output and add on QtableWidgets '''
        ParentMaster = QStandardItem('[ {0[src]} > {0[dst]} ] {1[Method]} {1[Host]}{1[Path]}'.format(
            data['urlsCap']['IP'], data['urlsCap']['Headers']))
        ParentMaster.setIcon(QIcon('icons/accept.png'))
        ParentMaster.setSizeHint(QSize(30, 30))
        for item in data['urlsCap']['Headers']:
            ParentMaster.appendRow([QStandardItem('{}'.format(item)),
                                    QStandardItem(data['urlsCap']['Headers'][item])])
        self.model.appendRow(ParentMaster)
        self.maindockwidget.setFirstColumnSpanned(ParentMaster.row(),
                                   self.maindockwidget.rootIndex(), True)
        self.maindockwidget.scrollToBottom()

    def clear(self):
        self.model.clear()

    def stopProcess(self):
        self.maindockwidget.clearSelection()
class URLMonitor(MitmMode):
    Name = "URLMonitor"
    Author = "Pumpkin-Dev"
    ID = "URLMonitor"
    Description = "Monitor the network connection and displays the list of intercepted URLs and HTTP header"
    Icon = "icons/tcpproxy.png"
    LogFile = C.LOG_URLCAPTURE
    _cmd_array = []
    ModSettings = True
    ModType = "proxy"  # proxy or server
    def __init__(self,parent,FSettingsUI=None,main_method=None,  **kwargs):
        super(URLMonitor, self).__init__(parent)
        self.dockwidget = URLMonitorDock(None,title=self.Name)
    @property
    def CMD_ARRAY(self):
        return None


