from core.servers.http_handler.proxyhandler.MitmMode import MitmMode
import core.utility.constants as C
from collections import OrderedDict
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.Qt import *

from core.widgets.docks.dock import DockableWidget
class NetCredential(DockableWidget):
    id = "NetCredential"
    title = "Net Crendential"
    def __init__(self,parent=None,title="",info={}):
        super(NetCredential,self).__init__(parent,title,info)
        self.setObjectName(self.title)
        self.maindockwidget = QTableWidget()
        self.maindockwidget.setColumnCount(4)
        self.maindockwidget.resizeRowsToContents()
        self.maindockwidget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.maindockwidget.horizontalHeader().setStretchLastSection(True)
        self.maindockwidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.maindockwidget.verticalHeader().setVisible(False)
        self.maindockwidget.verticalHeader().setDefaultSectionSize(27)
        self.maindockwidget.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('Username',[]),('Password',[]),('Url',[]),('Source/Destination',[])])
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())
        self.maindockwidget.horizontalHeader().resizeSection(0,120)
        self.maindockwidget.horizontalHeader().resizeSection(1,120)
        self.maindockwidget.horizontalHeader().resizeSection(2,180)
        self.setWidget(self.maindockwidget)

    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets '''
        self.THeaders['Username'].append(data['POSTCreds']['User'])
        self.THeaders['Password'].append(data['POSTCreds']['Pass'])
        self.THeaders['Url'].append(data['POSTCreds']['Url'])
        self.THeaders['Source/Destination'].append(data['POSTCreds']['Destination'])
        Headers = []
        self.maindockwidget.setRowCount(len(self.THeaders['Username']))
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QTableWidgetItem(item)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                self.maindockwidget.setItem(m, n, item)
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())
        self.maindockwidget.verticalHeader().setDefaultSectionSize(27)
        self.maindockwidget.scrollToBottom()

    def stopProcess(self):
        self.maindockwidget.setRowCount(0)
        self.maindockwidget.clearContents()
        self.maindockwidget.setHorizontalHeaderLabels(self.THeaders.keys())

class CredMonitor(MitmMode):
    Name = "CredMonitor"
    ID = "CredMonitor"
    Author = "Pumpkin-Dev"
    Description = "Sniff data/passwords packets as they are transmitted over HTTP protocol."
    Icon = "icons/tcpproxy.png"
    LogFile = C.LOG_CREDSCAPTURE
    _cmd_array = []
    ModSettings = True
    ModType = "proxy"  # proxy or server
    def __init__(self,parent,FSettingsUI=None,main_method=None,  **kwargs):
        super(CredMonitor, self).__init__(parent)
        self.dockwidget = NetCredential(None,title=self.Name)
    @property
    def CMD_ARRAY(self):
        return None


