from core.servers.http_handler.proxyhandler.MitmMode import MitmMode
import core.utility.constants as C
from collections import OrderedDict
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.Qt import *

from core.widgets.docks.dock import DockableWidget
class FirelambDock(DockableWidget):
    id = "Firelamb"
    title = "Firelamb"
    def __init__(self,parent=None,title="",info={}):
        super(FirelambDock,self).__init__(parent,title,info)
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
        self.maindockwidget.model.appendRow(ParentMaster)
        self.maindockwidget.setFirstColumnSpanned(ParentMaster.row(),
                                   self.rootIndex(), True)
        self.maindockwidget.scrollToBottom()

    def clear(self):
        self.model.clear()

    def stopProcess(self):
        self.maindockwidget.clearSelection()
class Firelamb(MitmMode):
    Name = "Firelamb"
    Author = "Wahyudin Aziz"
    ID = "Firelamb"
    Description = "Sniff passwords and hashes from an interface or pcap file coded by: Dan McInerney"
    Icon = "icons/tcpproxy.png"
    LogFile = C.LOG_CREDSCAPTURE
    _cmd_array = []
    ModSettings = True
    ModType = "proxy"  # proxy or server
    def __init__(self,parent,FSettingsUI=None,main_method=None,  **kwargs):
        super(Firelamb, self).__init__(parent)
        self.dockwidget = FirelambDock(None,title=self.Name)
    @property
    def CMD_ARRAY(self):
        self._cmd_array=[C.FIRELAMB_EXEC,'-i',str(self.Wireless.WLANCard.currentText())]
        return self._cmd_array


