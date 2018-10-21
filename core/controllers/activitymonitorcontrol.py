from core.config.globalimport import *
from core.widgets.docks.activitymonitor import *


class ActivityMonitorControl(QtGui.QGroupBox):
    monitor ={}
    addDock = QtCore.pyqtSignal(bool)
    def __init__(self,parent = None,**kwargs):
        super(ActivityMonitorControl,self).__init__(parent)
        self.setTitle("Activity Monitor")
        self.mainlayout = QtGui.QGridLayout()
        _actmon = [act(parent=self) for act in activitymonitor.ActivityMonitor.__subclasses__()]
        row=0
        col=0

        for i in _actmon:
            self.monitor[i.id]=i
            self.mainlayout.addWidget(i.controlui,row,col)
            row +=1

            if row==3:
                col +=1
        self.setLayout(self.mainlayout)


    def dockMonitorUpdate(self):
        pass

    @property
    def Active(self):
        active=[]
        for v in self.monitor.values():
            if v.controlui.isChecked():
                active.append(v)
        return active




