from core.loaders.models.PackagesUI import *
QWebView_checker = True
try:
    from PyQt4.QtWebKit import QWebView
except Exception:
    QWebView_checker = False
from os import getcwd,listdir
from shutil import copyfile
from os import path,mkdir

"""
Description:
    This program is a module for wifi-pumpkin.py. Report FIles Logger PDF or HTML

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

class frm_ReportLogger(PumpkinModule):
    ''' called report logger in files '''
    def __init__(self,sessions,parent = None):
        super(frm_ReportLogger, self).__init__(parent)
        self.setWindowTitle('WiFi-Pumpkin - Report Logger')
        self.setGeometry(0,0,320,400)
        self.Main     = QtGui.QVBoxLayout()
        self.sessions = sessions
        self.center()
        self.GUI()

    def addcheckListView_loggerFIles(self,unchecked,key,enable=None,checked=None,session=''):
        # add in listview all logger files
        empty = Refactor.exportHtml(unchecked,sessionID=session)[key]
        for loggerfile in empty:
            item = QtGui.QStandardItem(loggerfile)
            check = QtCore.Qt.Checked if checked == True else QtCore.Qt.Unchecked
            item.setCheckState(check)
            item.setEnabled(enable)
            item.setCheckable(True)
            self.model.appendRow(item)

    def get_all_items_Unchecked(self):
        # get all items desabled from row
        all_items_row = {}
        for index in range(self.model.rowCount()):
            item = self.model.item(index)
            if item.isCheckable() and item.checkState() == QtCore.Qt.Unchecked:
                all_items_row[str(item.text())] = False
        return  all_items_row

    def convertIt(self,printer):
        # generate file pdf
        self.ExportPDF.print_(printer)
        QtGui.QMessageBox.information(self, 'WiFi Pumpkin Report PDF', 'file PDF has been generated successfully.')

    def getImagesCapturedSession(self,session):
        ''' find images by session for export '''
        list_images = []
        if session == '':
            for image in listdir('logs/ImagesCap/'):
                list_images.append('{}/logs/ImagesCap/{}'.format(getcwd(),image))
            return list_images
        for image in listdir('logs/ImagesCap'):
            if session in image:
                list_images.append('{}/logs/ImagesCap/{}'.format(getcwd(),image))
        return list_images

    def ExportImagesCaptured(self,filename):
        ''' get images captured on session and copy to folter images_captured '''
        if len(filename[0]) != 0:
            pathdir = path.dirname(str(filename[0]))+'/images_captured/'
            if self.files_images != []:
                if not path.exists(pathdir):
                    mkdir(pathdir)
                for file in self.files_images:
                    copyfile(file,pathdir+path.basename(file))

    def exportFilesSystem(self):
        # export HTML or pdf file
        all_unchecked = self.get_all_items_Unchecked()
        if not self.checkHTML.isChecked() and not self.checkPDF.isChecked():
            return QtGui.QMessageBox.warning(self, 'WiFi Pumpkin Options',
            'You have to select a <strong>option</strong> file type  for export.')
        if  len(all_unchecked.keys()) == Refactor.exportHtml(all_unchecked,'')['Count']:
            return QtGui.QMessageBox.warning(self, 'WiFi Pumpkin empty session',
            'logger:ERROR Could not find log files.')

        sessions_activated = ''
        apname = self.configure.Settings.get_setting('accesspoint','APname')
        for key in self.sessions.keys():
            if str(self.CB_Data_Logger.currentText()) == self.sessions[key]['started']:
                contents = Refactor.exportHtml(all_unchecked,key,
                [self.sessions[key]['started'],self.sessions[key]['stoped']],apname)
                sessions_activated = key
                break
        self.files_images  =  self.getImagesCapturedSession(sessions_activated)
        if sessions_activated == '':
            contents = Refactor.exportHtml(all_unchecked,sessions_activated)

        if self.checkHTML.isChecked():
            filename = QtGui.QFileDialog.getSaveFileNameAndFilter(self,
            'Save File Logger as HTML','report.html','HTML (*.html)')
            if len(filename[0]) != 0:
                with open(str(filename[0]),'w') as filehtml:
                    filehtml.write(contents['HTML']),filehtml.close()
                QtGui.QMessageBox.information(self, 'WiFi Pumpkin Report HTML', 'file logs has been saved successfully.')

        elif self.checkPDF.isChecked():
            filename = QtGui.QFileDialog.getSaveFileNameAndFilter(self,
            'Save File Logger as PDF','report.pdf','PDF (*.pdf)')
            if len(filename[0]) != 0:
                self.ExportPDF.setHtml(contents['HTML'])
                printer = QtGui.QPrinter()
                printer.setPageSize(QtGui.QPrinter.A4)
                printer.setOutputFormat(QtGui.QPrinter.PdfFormat)
                printer.setOutputFileName(filename[0])
                self.convertIt(printer)

        self.ExportImagesCaptured(filename)

    @QtCore.pyqtSlot(QtCore.QModelIndex)
    def combo_clicked(self, session):
        # get  activated logger files
        self.model.clear()
        sessions_activated = ''
        for key in self.sessions.keys():
            if session == self.sessions[key]['started']:
                self.labelStart.setText(self.sessions[key]['started'])
                self.labelStop.setText(self.sessions[key]['stoped'])
                sessions_activated = key
                break
        all_unchecked = self.get_all_items_Unchecked()
        self.addcheckListView_loggerFIles(all_unchecked,'activated_Files',enable=True,
        checked=True,session=sessions_activated)
        self.addcheckListView_loggerFIles(all_unchecked,'empty_files',enable=False,
        checked=False,session=sessions_activated)

    def GUI(self):
        self.frm0       = QtGui.QFormLayout()
        self.model      = QtGui.QStandardItemModel()
        self.viewlogger = QtGui.QListView()
        self.widget = QtGui.QWidget()
        self.layout = QtGui.QVBoxLayout(self.widget)

        if QWebView_checker:
            self.ExportPDF = QWebView()

        # check all files logger empty or round
        self.viewlogger.setModel(self.model)
        self.layout.addLayout(self.frm0)

        # group file type
        self.GroupBoxFile    = QtGui.QGroupBox()
        self.layoutGroupFile = QtGui.QVBoxLayout()
        self.GroupBoxFile.setLayout(self.layoutGroupFile)
        self.GroupBoxFile.setTitle('Options:')
        self.checkHTML   = QtGui.QRadioButton('HTML')
        self.checkPDF    = QtGui.QRadioButton('PDF')
        self.checkPDF.setEnabled(QWebView_checker)
        self.layoutGroupFile.addWidget(self.checkHTML)
        self.layoutGroupFile.addWidget(self.checkPDF)

        # group informations
        self.GroupBoxINFO    = QtGui.QGroupBox()
        self.layoutGroupINFO = QtGui.QFormLayout()
        self.GroupBoxINFO.setLayout(self.layoutGroupINFO)
        self.GroupBoxINFO.setTitle('Information:')
        self.labelStart = QtGui.QLabel()
        self.labelStop = QtGui.QLabel()
        self.layoutGroupINFO.addRow('started AP at:',self.labelStart)
        self.layoutGroupINFO.addRow('stoped AP at:',self.labelStop)

        # get all session data add combobox
        self.CB_Data_Logger = QtGui.QComboBox(self)
        all_sessions = []
        for key in self.sessions.keys():
            all_sessions.append(self.sessions[key]['started'])
        all_sessions.append('select All logger file...')
        self.CB_Data_Logger.addItems(all_sessions)
        self.connect(self.CB_Data_Logger, QtCore.SIGNAL('activated(QString)'), self.combo_clicked)
        index = self.CB_Data_Logger.findText(all_sessions[len(all_sessions)-2], QtCore.Qt.MatchFixedString)
        self.CB_Data_Logger.setCurrentIndex(index)
        self.combo_clicked(self.CB_Data_Logger.currentText())

        self.btnSave = QtGui.QPushButton('Export')
        self.btnSave.clicked.connect(self.exportFilesSystem)

        self.frm0.addRow('Session:',self.CB_Data_Logger)
        self.frm0.addRow(self.GroupBoxINFO)
        self.frm0.addRow(self.viewlogger)
        self.frm0.addRow(self.GroupBoxFile)
        self.frm0.addRow(self.btnSave)

        self.Main.addWidget(self.widget)
        self.setLayout(self.Main)