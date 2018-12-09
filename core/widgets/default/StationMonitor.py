from core.config.globalimport import *
from core.widgets.default.uimodel import *
from datetime import datetime

class StationMonitor(TabsWidget):
    Name = "Station Monitor"
    ID = "StationMonitor"
    Icon = "icons/stations.png"
    __subitem = False
    def __init__(self,parent= None,FSettings=None):
        super(StationMonitor,self).__init__(parent,FSettings)
        self.FSettings = SuperSettings.getInstance()
        self.Home = QtGui.QVBoxLayout()
        self.widget = QtGui.QWidget()
        self.layout = QtGui.QVBoxLayout(self.widget)

        # self.GroupMonitor = QtGui.QGroupBox()
        self.MonitorTreeView = QtGui.QTreeView()
        self.MonitorTreeView.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.model = QtGui.QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Devices', 'Informations'])
        self.MonitorTreeView.setModel(self.model)
        self.MonitorTreeView.setUniformRowHeights(True)
        self.MonitorTreeView.setColumnWidth(0, 130)

        # self.GroupMonitor.setTitle('Station Monitor AP:')
        # self.GroupMonitor.setFixedHeight(400)
        # self.MonitorLayout = QtGui.QVBoxLayout()
        # self.MonitorLayout.addWidget(self.MonitorTreeView)
        # self.GroupMonitor.setLayout(self.MonitorLayout)
        self.scroll.setWidget(self.MonitorTreeView)
        # #self.mainlayout.addWidget(self.GroupMonitor)

    def addRequests(self, macddress, user, status):
        if status:
            ParentMaster = QtGui.QStandardItem('Connected:: {} at {}'.format(macddress,
                                                                             datetime.now().strftime("%H:%M")))
            ParentMaster.setIcon(QtGui.QIcon('icons/connected.png'))
            ParentMaster.setSizeHint(QtCore.QSize(30, 30))
            info1 = QtGui.QStandardItem('{}'.format(user['device']))
            info2 = QtGui.QStandardItem('{}'.format(user['IP']))
            info3 = QtGui.QStandardItem('{}'.format(datetime.now().strftime("%Y-%m-%d %H:%M")))
            ParentMaster.appendRow([QtGui.QStandardItem('Device::'), info1])
            ParentMaster.appendRow([QtGui.QStandardItem('IPAddr::'), info2])
            ParentMaster.appendRow([QtGui.QStandardItem('Current date::'), info3])
            self.model.appendRow(ParentMaster)
            return self.MonitorTreeView.setFirstColumnSpanned(ParentMaster.row(),
                                                              self.MonitorTreeView.rootIndex(), True)

        ParentMaster = QtGui.QStandardItem('Disconnected:: {} at {}'.format(macddress,
                                                                            datetime.now().strftime("%H:%M")))
        ParentMaster.setIcon(QtGui.QIcon('icons/disconnected.png'))
        ParentMaster.setSizeHint(QtCore.QSize(30, 30))
        info1 = QtGui.QStandardItem('{}'.format(user['device']))
        info2 = QtGui.QStandardItem('{}'.format(user['IP']))
        info3 = QtGui.QStandardItem('{}'.format(datetime.now().strftime("%Y-%m-%d %H:%M")))
        ParentMaster.appendRow([QtGui.QStandardItem('Device::'), info1])
        ParentMaster.appendRow([QtGui.QStandardItem('IPAddr::'), info2])
        ParentMaster.appendRow([QtGui.QStandardItem('Current date::'), info3])
        self.model.appendRow(ParentMaster)
        self.MonitorTreeView.setFirstColumnSpanned(ParentMaster.row(),
                                                   self.MonitorTreeView.rootIndex(), True)
