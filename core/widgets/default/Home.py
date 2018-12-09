from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.Qt import *
from core.widgets.default.uimodel import *



class Home(TabsWidget):
    Name = "Home"
    ID = "Home"
    Icon = "icons/home.png"
    __subitem = False
    def __init__(self,parent= None,FSettings=None):
        super(Home,self).__init__(parent,FSettings)
        self.__homeitem = [hi(parent) for hi in HomeDisplay.__subclasses__()]

        for wid in self.__homeitem:
            self.mainlayout.addWidget(wid)
            setattr(self,wid.ID,wid)
