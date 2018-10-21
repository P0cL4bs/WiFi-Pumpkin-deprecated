from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.Qt import *
from re import search
import modules as GUIs
from core.utils import Refactor
from collections import OrderedDict
from core.widgets.pluginssettings import BDFProxySettings,ResponderSettings
from core.widgets.default.uimodel import *



class Plugins(TabsWidget):
    Name = "Plugins"
    ID = "Plugins"
    Icon = "icons/plugins-new.png"
    __subitem = False
    sendSingal_disable = pyqtSignal(object)
    def __init__(self,parent,FSettings=None):
        super(Plugins,self).__init__(parent,FSettings)
        self.__plugins = [plug(parent) for plug in PluginsUI.__subclasses__()]
        for wid in self.__plugins:
            self.mainlayout.addWidget(wid)
            setattr(self,wid.Name,wid)


