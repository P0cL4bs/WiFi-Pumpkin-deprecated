from core.config.globalimport import *
from core.widgets.default.uimodel import *
import weakref
from core.widgets.default.SettingsItem import *

class SessionConfig(TabsWidget):
    ConfigRoot="Settings"
    Name = "Settings"
    ID = "SessionConfig"
    Icon = "icons/settings-AP.png"
    __subitem = False
    tablayout={}
    tabwidget={}
    instances=[]
    def __init__(self,parent=None,FSettings=None):
        super(SessionConfig,self).__init__(parent,FSettings)
        self.__class__.instances.append(weakref.proxy(self))
        self.FSettings = SuperSettings.getInstance()
        self.title = self.__class__.__name__
        self.tabcontainer = QtGui.QTabWidget()
        self.mainlayout.addWidget(self.tabcontainer)
        settingsItem = [setitem(self.parent ) for setitem in CoreSettings.__subclasses__()]
        self.settingsItem = {}
        for cat in sorted(settingsItem):
            self.tablayout[cat.Category] = QtGui.QVBoxLayout()
            self.tabwidget[cat.Category] = QtGui.QWidget()
            self.tabwidget[cat.Category].setLayout(self.tablayout[cat.Category])
        for k,v in self.tabwidget.items():
            self.tabcontainer.addTab(v,k)
        for mod in sorted(settingsItem):
            self.settingsItem[mod.title]=mod
            self.tablayout[mod.Category].addWidget(mod)
            #self.mainlayout.addWidget(mod)
            #Hack to add all the modules into class
            setattr(self.__class__,mod.ID,mod)

    @property
    def isSubitem(self):
        return self.__subitem

    @classmethod
    def getInstance(cls):
        return cls.instances[0]


