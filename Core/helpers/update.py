import time
from os import path
from subprocess import check_output,CalledProcessError
from Core.loaders.master.github import GithubUpdate,UrllibDownload
from Core.loaders.Stealth.PackagesUI import *


"""
Description:
    This program is a module for wifi-pumpkin.py. GUI update from github

Copyright:
    Copyright (C) 2015 Marcos Nesster P0cl4bs Team
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

class frm_githubUpdate(PumpkinModule):
    ''' called update from github repository master'''
    def __init__(self,version,parent = None):
        super(frm_githubUpdate, self).__init__(parent)
        self.setWindowTitle("WiFi-Pumpkin Software Update")
        self.loadtheme(self.configure.XmlThemeSelected())
        self.version = version
        self.UrlDownloadCommits = \
        'https://raw.githubusercontent.com/P0cL4bs/WiFi-Pumpkin/master/Core/config/commits/Lcommits.cfg'
        self.PathUrlRcommits = 'Core/config/commits/Rcommits.cfg'
        self.PathUrlLcommits = 'Core/config/commits/Lcommits.cfg'
        self.center()
        self.GUI()

    def GUI(self):
        self.Main       = QVBoxLayout()
        self.Blayout    = QHBoxLayout()
        self.frm        = QFormLayout()
        self.frmOutPut  = QFormLayout()
        self.frmCommits = QFormLayout()
        self.split      = QHBoxLayout()
        self.LVersion   = QLabel(self.version)
        self.pb         = ProgressBarWid(total=101)
        self.btnUpdate  = QPushButton('Install')
        self.btnCheck   = QPushButton('Check Updates')
        self.LCommits   = QListWidget(self)
        self.LOutput    = QListWidget(self)
        self.btnUpdate.setDisabled(True)

        # icons
        self.btnCheck.setIcon(QIcon('Icons/Checklist_update.png'))
        self.btnUpdate.setIcon(QIcon('Icons/updates_.png'))
        #connects
        self.btnCheck.clicked.connect(self.checkUpdate)
        self.btnUpdate.clicked.connect(self.startUpdate)
        #temporary

        # split left
        self.frmCommits.addRow(QLabel('New Commits::'))
        self.LCommits.setFixedWidth(255)
        self.frmCommits.addRow(self.LCommits)

        # split right
        self.frmOutPut.addRow(QLabel('Outputs::'))
        self.frmOutPut.addRow(self.LOutput)
        # blayout
        self.Blayout.addWidget(self.pb)
        self.Blayout.addWidget(self.btnCheck)
        self.Blayout.addWidget(self.btnUpdate)

        self.frm.addRow("Current Version:", self.LVersion)
        self.split.addLayout(self.frmCommits)
        self.split.addLayout(self.frmOutPut)
        self.frm.addRow(self.split)
        self.frm.addRow(self.Blayout)
        self.Main.addLayout(self.frm)
        self.setLayout(self.Main)

    def startUpdate(self):
        if hasattr(self,'git'):
            self.git.UpdateRepository()

    def checkUpdate(self):
        try:
            if not path.isfile(check_output(['which','git']).rstrip()):
                return QMessageBox.warning(self,'git','git is not installed')
        except CalledProcessError:
            return QMessageBox.warning(self,'git','git is not installed')
        self.LCommits.clear(),self.LOutput.clear()
        self.pb.setValue(1)
        self.btnCheck.setDisabled(True)
        self.downloaderUrl = UrllibDownload(self.UrlDownloadCommits)
        self.downloaderUrl.data_downloaded.connect(self.Get_ContentUrl)
        self.downloaderUrl.start()

    def Get_ContentUrl(self,data):
        if data == 'URLError':
            self.btnCheck.setEnabled(True)
            return QMessageBox.warning(self,'Update Warning','Checking internet connection failed.')
        self.git = GithubUpdate(self.version,data,self.PathUrlLcommits,self.PathUrlRcommits)
        self.connect(self.git,SIGNAL('Activated ( QString ) '), self.RcheckCommits)
        self.git.start()
        self.btnCheck.setDisabled(True)


    def RcheckCommits(self,commits):
        if 'no changes into' in commits:
            item = QListWidgetItem()
            item.setText(commits)
            item.setIcon(QIcon('Icons/checked_update.png'))
            item.setSizeHint(QSize(20,20))
            self.LCommits.addItem(item)
            return self.btnCheck.setEnabled(True)
        elif 'new Version available WiFi-Pumpkin v' in commits:
            reply = QMessageBox.question(self, 'Update Information',
                '{}, would you like to update??'.format(commits), QMessageBox.Yes |
                QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.git.NewVersionUpdate()
            return self.btnCheck.setEnabled(True)
        elif 'commit:' in commits:
            item = QListWidgetItem()
            item.setText(commits)
            item.setIcon(QIcon('Icons/check_update.png'))
            item.setSizeHint(QSize(20,20))
            self.LCommits.addItem(item)
            self.btnCheck.setEnabled(True)
            self.btnUpdate.setEnabled(True)
        elif 'alive::' in commits:
            self.pb.update_bar(10)
        elif '::updated' in commits:
            self.pb.update_bar(100)
            QMessageBox.information(self,'Update Information',
            "Already up-to-date. You're required to restart the tool to apply this update.")
            self.btnUpdate.setDisabled(True)
        else:
            self.LOutput.addItem(commits)


''' http://stackoverflow.com/questions/22332106/python-qtgui-qprogressbar-color '''
class ProgressBarWid(QProgressBar):
    def __init__(self, parent=None, total=0):
        super(ProgressBarWid, self).__init__()
        self.setMinimum(1)
        self.setMaximum(total)
        self._active = False
        self.setAlignment(Qt.AlignCenter)
        self._text = None

    def setText(self, text):
        self._text = text

    def text(self):
        if self._text != None:
            return QString(str(self._text))
        return QString('')

    def update_bar_simple(self, add):
        value = self.value() + add
        self.setValue(value)
        if value > 50:
            self.change_color("green")

    def update_bar(self, add):
        while True:
            time.sleep(0.01)
            value = self.value() + add
            self.setValue(value)
            if value > 50:
                self.change_color("green")
            qApp.processEvents()
            if (not self._active or value >= self.maximum()):
                break
        self._active = False

    def closeEvent(self, event):
        self._active = False

    def change_color(self, color):
        template_css = """QProgressBar::chunk { background: %s; }"""
        css = template_css % color
        self.setStyleSheet(css)