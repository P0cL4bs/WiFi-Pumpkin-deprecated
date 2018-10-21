from configobj import ConfigObj
import core.utility.constants as C
from core.loaders.models.PackagesUI import *
from core.servers.http_handler.proxyhandler.MitmMode import MitmMode


class Responder(MitmMode):
    Name = "Responder"
    Author = "Pumpkin-Dev"
    ID = "Responder"
    Description = "Responder an LLMNR, NBT-NS and MDNS poisoner By default, the tool will only answer to File Server Service request, which is for SMB."
    Icon = "icons/tcpproxy.png"
    LogFile = C.LOG_RESPONDER
    ModSettings = True
    ModType = "proxy"  # proxy or server
    _cmd_array = []
    def __init__(self,parent,FSettingsUI=None,main_method=None,  **kwargs):
        super(Responder, self).__init__(parent)
        self.ConfigWindow = ResponderSettings()
    @property
    def CMD_ARRAY(self):
        self._cmd_array=[C.RESPONDER_EXEC,'-I', str(self.Wireless.WLANCard.currentText()),'-wrFbv']
        return self._cmd_array


class ResponderSettings(PumpkinModule):
    def __init__(self,parent=None):
        super(ResponderSettings, self).__init__(parent)
        self.setWindowTitle('Responder Plugin settings')
        self.setGeometry(0,0,480, 500)
        self.main       = QtGui.QVBoxLayout()
        self.THeaders   = {'Config':[],'Value':[] }
        self.userConfig = ConfigObj(str(self.configure.Settings.get_setting('plugins','responder_config')))
        self.userConfig.interpolation = False
        self.center()
        self.GUI()

    def addRowTableWidget(self, _key, _value):
        ''' add items into TableWidget '''
        Headers = []
        self.THeaders['Config'].append(_key)
        self.THeaders['Value'].append(_value)
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QtGui.QTableWidgetItem(item)
                item.setFlags(item.flags() | QtCore.Qt.ItemIsEditable)
                self.TabSettings.setItem(m, n, item)
        self.TabSettings.resizeColumnToContents(0)

    def getAllRowTablesWidget(self):
        ''' dump all setting into table for list'''
        model = self.TabSettings.model()
        data,datafilter = [],[]
        for row in range(model.rowCount()):
            data.append([])
            for column in range(model.columnCount()):
                index = model.index(row, column)
                data[row].append(str(model.data(index).toString()))
        for key,item in data:
            datafilter.append(key)
            datafilter.append(item)
        return datafilter
    def addAllconfigKeys(self):
        ''' get all settings and add into table'''
        for key in self.userConfig.keys():
            for items in self.userConfig[key].items():
                self.addRowTableWidget(items[0],items[1])

    def checkConfigKeysResponder(self,saveObjct=False,count=False):
        ''' check number row and save settings '''
        if count:
            lenconfig = 0
            for key in self.userConfig.keys():
                for items in self.userConfig[key].items(): lenconfig += 1
            return lenconfig
        if saveObjct:
            settings = self.getAllRowTablesWidget()
            for key in self.userConfig.keys():
                for items in self.userConfig[key].items():
                    self.userConfig[key][items[0]] = settings[settings.index(items[0])+1]
            self.userConfig.write()
    def saveConfigObject(self):
        self.checkConfigKeysResponder(saveObjct=True)
        QtGui.QMessageBox.information(self,'Responder settings','All settings in {} has been saved '
        'with success.'.format(str(self.configure.Settings.get_setting('plugins','responder_config'))))
        self.close()

    def GUI(self):
        self.TabSettings = QtGui.QTableWidget(self.checkConfigKeysResponder(count=True),2)
        self.btnSave     = QtGui.QPushButton('Save settings')
        self.GroupBox    = QtGui.QGroupBox(self)
        self.widget      = QtGui.QWidget()
        self.layoutGroup = QtGui.QVBoxLayout(self.widget)
        self.GroupBox.setLayout(self.layoutGroup)
        self.GroupBox.setTitle('Options')
        self.addAllconfigKeys()
        self.btnSave.clicked.connect(self.saveConfigObject)
        self.TabSettings.resizeRowsToContents()
        self.TabSettings.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.TabSettings.horizontalHeader().setStretchLastSection(True)
        self.TabSettings.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        #self.TabSettings.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.TabSettings.verticalHeader().setVisible(False)
        self.TabSettings.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabSettings.verticalHeader().setDefaultSectionSize(23)

        self.layout = QtGui.QVBoxLayout(self.widget)
        self.layoutGroup.addWidget(self.TabSettings)
        self.layout.addWidget(self.GroupBox)
        self.layout.addWidget(self.btnSave)
        self.main.addWidget(self.widget)
        self.setLayout(self.main)