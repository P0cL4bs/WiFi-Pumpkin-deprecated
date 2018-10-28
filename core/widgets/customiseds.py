from PyQt4 import QtGui, QtCore
from core.utils import Refactor
from core.utility.collection import SettingsINI
import core.utility.constants as C

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for custom widgets.

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


class AutoGridLayout(QtGui.QGridLayout):
    def __init__(self):
        QtGui.QGridLayout.__init__(self)
        self.column     = 0
        self.max_column = 1
        self.row        = 0

    def addNextWidget(self, widget):
        self.addWidget(widget, self.row, self.column)
        self.column += 1
        if self.column > self.max_column:
            self.row += 1
            self.column = 0

class AutoTableWidget(QtGui.QTableWidget):
    def __init__(self):
        QtGui.QTableWidget.__init__(self)
        self.column,self.row = 0,0
        self.max_column     = 4
        self.loadtheme(SettingsINI(C.CONFIG_INI).get_setting('settings', 'themes'))
        self.items_widgets  = {}
        self.APclients      = {}
        self.setColumnCount(self.max_column)

    def loadtheme(self,theme):
        ''' load Theme from file .qss '''
        sshFile=("core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def clearInfoClients(self):
        self.APclients = {}
        self.column, self.row = 0, 0
        self.clearContents()

    def addNextWidget(self, agent={}):
        ''' auto add item in table '''
        self.items_widgets[agent.keys()[0]] = {}
        self.APclients[agent.keys()[0]] = agent[agent.keys()[0]]
        for key in agent.keys():
            #for client in agent[key].keys():
            for client in agent[key]:
                item = QtGui.QTableWidgetItem(agent[key][client])
                item.setTextAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignCenter)
                self.setItem(self.row, self.column, item)
                self.items_widgets[key][client] = item
                self.inc_auto()

    def delete_item(self,mac_address):
        ''' detelte item by mac_address '''
        if mac_address in self.APclients.keys():
            for row in xrange(0,self.rowCount()):
                if self.item(row,2) != None:
                    if self.item(row,2).text() == mac_address:
                        self.removeRow(row)
                        del self.APclients[mac_address]
            self.reset_inc() # reset increment and re-add all clients in table

            temp = {}
            for key_mac,dict_agent in self.APclients.iteritems():
                temp[key_mac] = dict_agent
                self.addNextWidget(temp)
                temp.clear() # reset temp 

    def get_connected_clients(self):
        ''' get amount client connected '''
        return len(self.APclients.keys())

    def inc_auto(self):
        self.column += 1
        if self.column >= self.max_column:
            self.row     += 1
            self.column   = 0

    def reset_inc(self):
        self.column = 0
        self.row    = 0
