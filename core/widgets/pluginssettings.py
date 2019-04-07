from configobj import ConfigObj,Section
from collections import OrderedDict
import modules as GUI
from core.loaders.models.PackagesUI import *
import core.utility.constants as C
import os
from functools import partial
"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    config plugins .

Copyright:
    Copyright (C) 2015-2017 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

class BDFProxySettings(PumpkinModule):
    def __init__(self,parent=None):
        super(BDFProxySettings, self).__init__(parent)
        self.setWindowTitle('DBFProxy-ng Plugin settings')
        self.setGeometry(0,0,480, 500)
        self.main       = QtGui.QVBoxLayout()
        self.THeaders   = {'Config':[],'Value':[] }
        self.userConfig = ConfigObj(str(self.configure.Settings.get_setting('plugins','bdfproxy_config')))
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
        ''' dump all settings from table '''
        model = self.TabSettings.model()
        data,datafilter,self.key = [],OrderedDict(),None
        for row in range(model.rowCount()):
            data.append([])
            for column in range(model.columnCount()):
                index = model.index(row, column)
                data[row].append(str(model.data(index).toString()))
        datafilter['ESP'] = {}
        datafilter['LinuxIntelx86'] = {}
        datafilter['LinuxIntelx64'] = {}
        datafilter['WindowsIntelx86'] = {}
        datafilter['WindowsIntelx64'] = {}
        datafilter['MachoIntelx86'] = {}
        datafilter['MachoIntelx64'] = {}
        for count,item in enumerate(data):
            if count < 5:
                if item[0] != '' or item[1] != '':
                    datafilter['ESP'][item[0]] = item[1]
            else:
                if item[0] != '' or item[1] != '':
                    if item[1] in datafilter.keys():
                        self.key = item[1]
                    else:
                        datafilter[self.key][item[0]] = item[1]
        return datafilter

    def saveConfigObject(self):
        self.checkConfigKeysBDFProxy(saveObjct=True)
        QtGui.QMessageBox.information(self,'BDFProxy-ng settings','All settings in {} has been saved '
        'with success.'.format(str(self.configure.Settings.get_setting('plugins','bdfproxy_config'))))
        self.close()

    def checkConfigKeysBDFProxy(self,saveObjct=False):
        ''' save all change into file.conf '''
        if saveObjct: changedData = self.getAllRowTablesWidget()
        for target in self.userConfig['targets'].keys():
            if target == 'ALL':
                for item in self.userConfig['targets']['ALL']:
                    if type(self.userConfig['targets']['ALL'][item]) == str:
                        if saveObjct:
                            self.userConfig['targets']['ALL'][item] = changedData['ESP'][item]
                        else:
                            self.addRowTableWidget(item,self.userConfig['targets']['ALL'][item])
                    elif type(self.userConfig['targets']['ALL'][item]) == Section:
                        if saveObjct:
                            self.userConfig['targets']['ALL'][item] = changedData[item]
                        else:
                            self.addRowTableWidget('-'*35+'>',item)
                            for key in self.userConfig['targets']['ALL'][item]:
                                self.addRowTableWidget(key,self.userConfig['targets']['ALL'][item][key])
        if saveObjct: self.userConfig.write()

    def GUI(self):
        self.TabSettings = QtGui.QTableWidget(50,2)
        self.btnSave     = QtGui.QPushButton('Save settings')
        self.GroupBox    = QtGui.QGroupBox(self)
        self.widget      = QtGui.QWidget()
        self.layoutGroup = QtGui.QVBoxLayout(self.widget)
        self.GroupBox.setLayout(self.layoutGroup)
        self.GroupBox.setTitle('Options')
        self.checkConfigKeysBDFProxy()
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


class ResponderSettings(PumpkinModule):
    def __init__(self,parent=None):
        super(ResponderSettings, self).__init__(parent)
        self.setWindowTitle('Firelamb Plugin settings')
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
        QtGui.QMessageBox.information(self,'Firelamb settings','All settings in {} has been saved '
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

class PumpkinProxySettings(PumpkinModule):
    def __init__(self,plugin,items,parent=None):
        super(PumpkinProxySettings, self).__init__(parent)
        self.setWindowTitle('Settings: {} '.format(plugin[4:]))
        self.THeaders   = {'Config':[],'Value':[] }
        self.config     = SettingsINI(C.PUMPPROXY_INI)
        self.main       = QtGui.QVBoxLayout()
        self.plugin_items = items
        self.plugin_key = plugin
        self.setGeometry(0,0,400, 250)
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

    def saveConfigObject(self):
        ''' get all key and value and save '''
        data = []
        model = self.TabSettings.model()
        for row in range(model.rowCount()):
            data.append([])
            for column in range(model.columnCount()):
                index = model.index(row, column)
                data[row].append(str(model.data(index).toString()))
        for key,item in data:
            self.config.set_setting(self.plugin_key,key,item)
        self.close()

    def GUI(self):
        self.TabSettings = QtGui.QTableWidget(len(self.plugin_items),2)
        self.btnSave     = QtGui.QPushButton('Save settings')
        self.GroupBox    = QtGui.QGroupBox(self)
        self.widget      = QtGui.QWidget()
        self.layoutGroup = QtGui.QVBoxLayout(self.widget)
        self.GroupBox.setLayout(self.layoutGroup)
        self.GroupBox.setTitle('Options')
        self.btnSave.clicked.connect(self.saveConfigObject)
        self.TabSettings.resizeRowsToContents()
        self.TabSettings.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.TabSettings.horizontalHeader().setStretchLastSection(True)
        self.TabSettings.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        #self.TabSettings.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.TabSettings.verticalHeader().setVisible(False)
        self.TabSettings.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabSettings.verticalHeader().setDefaultSectionSize(23)

        for item in self.plugin_items:
            self.addRowTableWidget(item,self.config.get_setting(self.plugin_key,item))

        self.layout = QtGui.QVBoxLayout(self.widget)
        self.layoutGroup.addWidget(self.TabSettings)
        self.layout.addWidget(self.GroupBox)
        self.layout.addWidget(self.btnSave)
        self.main.addWidget(self.widget)
        self.setLayout(self.main)
        
class CaptivePortalSettings(PumpkinModule):
    def __init__(self,plugin,items,parent=None):
        super(CaptivePortalSettings, self).__init__(parent)
        self.setWindowTitle('Settings: {} '.format(plugin[4:]))
        self.THeaders   = {'Language':[] }
        self.config     = SettingsINI(C.CAPTIVEPORTAL_INI)
        self.main       = QtGui.QVBoxLayout()
        self.plugin_items = items
        self.plugin_key = plugin
        self.options = {}
        self.setGeometry(0,0,300, 250)
        self.center()
        self.GUI()

    def addRowTableWidget(self, _key, _value):
        ''' add items into TableWidget '''
        self.options[_key] = QtGui.QRadioButton(_key)
        self.options[_key].setObjectName(_key)
        self.options[_key].setChecked(_value)
        self.SettingsLayout.addRow(self.options[_key])
        self.options[_key].clicked.connect(partial(self.setPluginOption,self.options[_key].objectName()))

    def setPluginOption(self, name,status):
        ''' get each plugins status'''
        # enable realtime disable and enable plugin
        self.config.set_setting(self.plugin_key,name,status)
        for plugin in self.plugin_items:
            if (plugin != name):
                self.config.set_setting(self.plugin_key,plugin,False)

    def GUI(self):
        self.TabSettings = QtGui.QTableWidget(len(self.plugin_items),2)
        self.GroupBox    = QtGui.QGroupBox(self)
        self.widget      = QtGui.QWidget()
        self.layoutGroup = QtGui.QVBoxLayout(self.widget)
        self.GroupBox.setLayout(self.layoutGroup)
        self.GroupBox.setTitle('Options')


        self.GroupSettings  = QtGui.QGroupBox()
        self.GroupSettings.setTitle('Language settings:')
        self.SettingsLayout = QtGui.QFormLayout()
        self.GroupSettings.setLayout(self.SettingsLayout)

        for item in self.plugin_items:
            self.addRowTableWidget(item,self.config.get_setting(self.plugin_key,item, format=bool))

        self.layout = QtGui.QVBoxLayout(self.widget)
        self.layoutGroup.addWidget(self.GroupSettings)
        self.layout.addWidget(self.GroupBox)
        self.main.addWidget(self.widget)
        self.setLayout(self.main)

class LabelImageViewResize(QtGui.QWidget):
    #https://stackoverflow.com/questions/44505229/pyqt-automatically-resizing-widget-picture
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent=parent)
        self.p = QtGui.QPixmap()

    def setPixmap(self, p):
        self.p = p
        self.update()

    def paintEvent(self, event):
        if not self.p.isNull():
            painter = QtGui.QPainter(self)
            painter.setRenderHint(QtGui.QPainter.SmoothPixmapTransform)
            painter.drawPixmap(self.rect(), self.p)


class CaptivePortalPreviewImage(PumpkinModule):
    def __init__(self,plugin,image,parent=None):
        super(CaptivePortalPreviewImage, self).__init__(parent)
        self.setWindowTitle('Preview Captive Portal: {} '.format(plugin))
        self.image_preview = image
        self.setGeometry(0,0,500, 400)
        self.main  = QtGui.QVBoxLayout()
        self.center()
        self.GUI()

    def GUI(self):
        self.widget      = QtGui.QWidget()
        self.layoutGroup = QtGui.QVBoxLayout(self.widget)
        self.GroupBox    = QtGui.QGroupBox(self)
        self.GroupBox.setLayout(self.layoutGroup)

        self.lb = LabelImageViewResize(self)
        self.pixmap = QtGui.QPixmap(os.getcwd() + "/{}".format(self.image_preview))
        self.lb.resize(1024, 720)
        self.lb.setPixmap(self.pixmap.scaled(self.lb.size(), QtCore.Qt.IgnoreAspectRatio))
        
        self.layout = QtGui.QVBoxLayout(self.widget)
        self.layoutGroup.addWidget(self.lb)
        self.layout.addWidget(self.GroupBox)
        self.main.addWidget(self.widget)
        self.setLayout(self.main)