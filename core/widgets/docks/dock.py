from PyQt4 import QtGui,QtCore,Qt
from functools import  partial

class DockableWidget(QtGui.QDockWidget):
    title = 'Default'
    id = 'default'
    Icon = "icons/tcpproxy.png"
    addDock = QtCore.pyqtSignal(object)
    def __init__(self,parent=0,t='Default',info={}):
        super(DockableWidget,self).__init__(t)
        self.parent = parent
        self.title = t
        self.logger = info
        self.startThread = False
        self.processThread = None
        self.setWindowIcon(QtGui.QIcon(self.Icon))
        self.setSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        self.setAllowedAreas(QtCore.Qt.AllDockWidgetAreas)
        self.setFeatures(QtGui.QDockWidget.DockWidgetMovable | QtGui.QDockWidget.DockWidgetFloatable)
        self.controlui = QtGui.QCheckBox(self.title)
        self.controlui.clicked.connect(partial(self.controlui_toggled))
        self.mainlayout = QtGui.QGridLayout()
        self.maindockwidget = QtGui.QListWidget()
        self.setWidget(self.maindockwidget)
    def runThread(self):
        self.startThread=True
    def controlui_toggled(self):
        if self.controlui.isChecked():
            self.addDock.emit(True)
        else:
            self.addDock.emit(False)
    def writeModeData(self,data):
        item = QtGui.QListWidgetItem()
        item.setText(data)
        item.setSizeHint(Qt.QSize(27, 27))
        #item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsEditable | Qt.ItemIsSelectable)
        self.maindockwidget.insertItem(self.maindockwidget.count() + 1, item)
        self.maindockwidget.scrollToBottom()
    def clear(self):
        pass
    def stopProcess(self):
        if self.processThread != None:
            self.processThread.stop()
