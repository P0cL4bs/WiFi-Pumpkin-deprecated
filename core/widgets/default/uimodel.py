from core.config.globalimport import *
import weakref


class OptionDialog(QtGui.QDialog):
    def __init__(self,parent=None):
        super(OptionDialog,self).__init__(parent)
        self.parent = parent
        self.setWindowTitle("{} Options".format(self.parent.ID))
        self.setMinimumSize(QtCore.QSize(300,100))

        self.layout = QtGui.QFormLayout()
        groupbox = QtGui.QGroupBox()
        groupbox.setTitle("Custom Options")
        self.content = QtGui.QFormLayout()
        groupbox.setLayout(self.content)
        self.btnOK = QtGui.QPushButton("OK")
        self.btnOK.clicked.connect(self.onOK)
        self.btnCancel = QtGui.QPushButton("Cancel")
        self.btnCancel.clicked.connect(self.onCancel)
        self.layout.addRow(groupbox)
        self.layout.addRow(self.btnOK,self.btnCancel)
        self.setLayout(self.layout)
    def onOK(self):
        pass
    def onCancel(self):
        self.close()
class TabsWidget(QtGui.QWidget):
    Name="Generic"
    ID = "Generic"
    Icon = ""
    __subitem = False
    sendMensage = QtCore.pyqtSignal(str)
    checkDockArea = QtCore.pyqtSignal(dict)
    def __init__(self,parent=0,FSettings=None):
        super(TabsWidget,self).__init__(parent)
        self.setObjectName(self.Name)
        #self.setTitle("{}".format(self.Name))
        self.FSettings = SuperSettings.getInstance()
        self.parent = parent

        self.tabinterface = QtGui.QListWidgetItem()
        self.tabinterface.setText(self.Name)
        self.tabinterface.setSizeHint(QtCore.QSize(30, 30))
        if self.Icon is not None:
            self.tabinterface.setIcon(QtGui.QIcon(self.Icon))
        self.mainlayout = QtGui.QVBoxLayout()
        self.scrollwidget = QtGui.QWidget()
        self.scroll = QtGui.QScrollArea()
        self.scrollwidget.setLayout(self.mainlayout)
        self.scroll.setWidgetResizable(True)
        self.scrollwidget.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.scroll.setWidget(self.scrollwidget)


        self.layout = QtGui.QVBoxLayout()
        self.layout.addWidget(self.scroll)
        self.setLayout(self.layout)

    @property
    def isSubitem(self):
        return self.__subitem


class CoreSettings(QtGui.QGroupBox):

    Name = "General"
    ID = "General"
    ConfigRoot = "General"
    Category="General"
    Icon=None
    __subitem=False
    conf={}


    def __init__(self,parent=0,FSettings=None):
        super(CoreSettings,self).__init__(parent)
        self.setObjectName(self.Name)
        self.setTitle("{} Settings".format(self.Name))
        self.setCheckable(True)
        self.parent = parent
        self.FSettings = SuperSettings.getInstance()
        self.layout = QtGui.QVBoxLayout()
        self.setLayout(self.layout)
    def deleteObject(self,obj):
        ''' reclaim memory '''
        del obj

    @property
    def isSubitem(self):
        return self.__subitem
    def osWalkCallback(self,arg,directory,files):
        pass



class HomeDisplay(QtGui.QWidget):
    Name = "HomeDisplay"
    ID = "Generic"
    Icon=None
    __subitem=False
    def __init__(self,parent=0,FSettings=None):
        super(HomeDisplay,self).__init__(parent)
        self.setObjectName(self.Name)
        self.FSettings = SuperSettings.getInstance()
        self.parent = parent


        self.mainlayout = QtGui.QVBoxLayout()
        self.scrollwidget = QtGui.QWidget()
        self.scroll = QtGui.QScrollArea()
        self.scrollwidget.setLayout(self.mainlayout)
        self.scroll.setWidgetResizable(True)
        self.scrollwidget.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.scroll.setWidget(self.scrollwidget)

        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.setLayout(self.layout)

    @property
    def isSubitem(self):
        return self.__subitem

class PluginsUI(QtGui.QGroupBox):
    Name = "Default"
    Caption = "Default"
    ID = "Generic"
    def __init__(self,parent=0):
        super(PluginsUI,self).__init__(parent)
        self.parent = parent
        self.FSettings = SuperSettings.getInstance()
        self.sessionconfig ={}
        self.setTitle(self.Caption)
        self.table = QtGui.QTableWidget()
        self.mainLayout = QtGui.QVBoxLayout()
        self.scrollwidget = QtGui.QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QtGui.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)

        self.mainLayout.addWidget(self.table)
        self.layout_table = QtGui.QHBoxLayout()
        self.layout_table.addWidget(self.scroll)
        self.setLayout(self.layout_table)

    @property
    def config(self):
        return self.sessionconfigcd
    def deleteObject(self,obj):
        del obj
