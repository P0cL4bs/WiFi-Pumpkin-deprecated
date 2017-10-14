import time
import fnmatch
from os import path,walk
from subprocess import check_output,CalledProcessError
from core.loaders.master.github import GithubUpdate,UrllibDownload
from core.loaders.models.PackagesUI import *


"""
Description:
    This program is a module for wifi-pumpkin.py. GUI update from github

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

class frm_githubUpdate(PumpkinModule):
    ''' called update from github repository master'''
    def __init__(self,version,parent = None):
        super(frm_githubUpdate, self).__init__(parent)
        self.setWindowTitle("WiFi-Pumpkin Software Update")
        self.checkHasCommits = False
        self.version = version
        self.UrlDownloadCommits = C.LCOMMITS
        self.PathUrlLcommits = self.get_file_cfg_Update('Core')
        self.PathUrlRcommits = self.PathUrlLcommits.replace('L','R')
        self.center()
        self.GUI()

    def GUI(self):
        self.Main       = QtGui.QVBoxLayout()
        self.widget     = QtGui.QWidget()
        self.layout     = QtGui.QVBoxLayout(self.widget)
        self.Blayout    = QtGui.QHBoxLayout()
        self.frmVersion = QtGui.QFormLayout()
        self.frmLabels  = QtGui.QHBoxLayout()
        self.frmOutPut  = QtGui.QHBoxLayout()
        self.frmCommits = QtGui.QHBoxLayout()
        self.split      = QtGui.QHBoxLayout()
        self.LVersion   = QtGui.QLabel(self.version)
        self.pb         = ProgressBarWid(total=101)
        self.btnUpdate  = QtGui.QPushButton('Install')
        self.btnCheck   = QtGui.QPushButton('Check Updates')
        self.LCommits   = QtGui.QListWidget(self)
        self.LOutput    = QtGui.QListWidget(self)
        self.LCommits.setSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        self.LOutput.setSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        self.btnUpdate.setDisabled(True)

        # icons
        self.btnCheck.setIcon(QtGui.QIcon('icons/Checklist_update.png'))
        self.btnUpdate.setIcon(QtGui.QIcon('icons/updates_.png'))
        #connects
        self.btnCheck.clicked.connect(self.checkUpdate)
        self.btnUpdate.clicked.connect(self.startUpdate)
        #temporary

        # split left
        self.frmLabels.addWidget(QtGui.QLabel('New Commits::'))
        self.frmCommits.addWidget(self.LCommits)

        # split right
        self.frmLabels.addWidget(QtGui.QLabel('Outputs::'))
        self.frmOutPut.addWidget(self.LOutput)
        # blayout
        self.Blayout.addWidget(self.pb)
        self.Blayout.addWidget(self.btnCheck)
        self.Blayout.addWidget(self.btnUpdate)

        self.frmVersion.addRow("Current Version:", self.LVersion)
        self.split.addLayout(self.frmCommits)
        self.split.addLayout(self.frmOutPut)

        self.layout.addLayout(self.frmVersion)
        self.layout.addLayout(self.frmLabels)
        self.layout.addLayout(self.split)
        self.layout.addLayout(self.Blayout)
        self.Main.addWidget(self.widget)
        self.setLayout(self.Main)

    def startUpdate(self):
        if hasattr(self,'git'):
            self.git.UpdateRepository()

    def get_file_cfg_Update(self,base_path):
        matches = []
        if not path.exists(base_path):
            base_path = base_path.lower()
        for root, dirnames, filenames in walk(base_path):
            for filename in fnmatch.filter(filenames, '*.cfg'):
                matches.append(path.join(root, filename))
        for filename in matches:
            if str(filename).endswith('Lcommits.cfg'):
                return filename

    def checkUpdate(self):
        try:
            if not path.isfile(check_output(['which','git']).rstrip()):
                return QtGui.QMessageBox.warning(self,'git','git is not installed')
        except CalledProcessError:
            return QtGui.QMessageBox.warning(self,'git','git is not installed')
        self.LCommits.clear(),self.LOutput.clear()
        self.pb.setValue(1)
        self.btnCheck.setDisabled(True)
        self.downloaderUrl = UrllibDownload(self.UrlDownloadCommits)
        self.downloaderUrl.data_downloaded.connect(self.Get_ContentUrl)
        self.downloaderUrl.start()

    def Get_ContentUrl(self,data):
        if data == 'URLError':
            return self.btnCheck.setEnabled(True)
        self.git = GithubUpdate(self.version,data,self.PathUrlLcommits,self.PathUrlRcommits)
        self.connect(self.git,QtCore.SIGNAL('Activated ( QString ) '), self.RcheckCommits)
        self.git.start()
        self.btnCheck.setDisabled(True)


    def RcheckCommits(self,commits):
        if 'no changes into' in commits:
            item = QtGui.QListWidgetItem()
            item.setText(commits)
            item.setIcon(QtGui.QIcon('icons/checked_update.png'))
            item.setSizeHint(QtCore.QSize(20,20))
            self.LCommits.addItem(item)
            return self.btnCheck.setEnabled(True)
        elif 'New version available WiFi-Pumpkin v' in commits:
            reply = QtGui.QMessageBox.question(self, 'Update Information',
                '{}, would you like to update??'.format(commits), QtGui.QMessageBox.Yes |
                QtGui.QMessageBox.No, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                self.git.NewVersionUpdate()
            return self.btnCheck.setEnabled(True)
        elif 'commit:' in commits:
            item = QtGui.QListWidgetItem()
            item.setText(commits)
            item.setIcon(QtGui.QIcon('icons/check_update.png'))
            item.setSizeHint(QtCore.QSize(20,20))
            self.LCommits.addItem(item)
            self.btnCheck.setEnabled(True)
            self.btnUpdate.setEnabled(True)
            self.checkHasCommits = True
        elif 'alive::' in commits:
            self.pb.update_bar(10)
        elif '::updated' in commits:
            self.pb.update_bar(100)
            QtGui.QMessageBox.information(self,'Update Information',
            "Already up-to-date. Please restart WiFi-Pumpkin to apply this update.")
            self.btnUpdate.setDisabled(True)
        else:
            self.LOutput.addItem(commits)


''' http://stackoverflow.com/questions/22332106/python-qtgui-qprogressbar-color '''
class ProgressBarWid(QtGui.QProgressBar):
    def __init__(self, parent=None, total=0):
        super(ProgressBarWid, self).__init__()
        self.setMinimum(1)
        self.setMaximum(total)
        font=QtGui.QFont('White Rabbit')
        font.setPointSize(5)
        self.setFont(font)
        self.effect = QtGui.QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.animationIn = QtCore.QPropertyAnimation(self.effect, 'opacity')
        self.animationIn.setDuration(300)
        self.animationIn.setStartValue(0)
        self.animationIn.setEndValue(1.0)
        self.animationIn.start()
        self._active = False
        self.setAlignment(QtCore.Qt.AlignCenter)
        self._text = None

    def hideProcessbar(self):
        self.animationOut = QtCore.QPropertyAnimation(self.effect, 'opacity')
        self.animationOut.setDuration(300)
        self.animationOut.setStartValue(1.0)
        self.animationOut.setEndValue(0)
        self.animationOut.start()
        self.animationOut.finished.connect(self.hide)

    def showProcessBar(self):
        self.animationIn = QtCore.QPropertyAnimation(self.effect, 'opacity')
        self.animationIn.setDuration(300)
        self.animationIn.setStartValue(0)
        self.animationIn.setEndValue(1.0)
        self.animationIn.start()
        self.show()

    def setText(self, text):
        self._text = text

    def text(self):
        if self._text != None:
            return QtCore.QString(str(self._text))
        return QtCore.QString('')

    def update_bar_simple(self, add):
        value = self.value() + add
        self.setValue(value)

    def update_bar(self, add):
        while True:
            time.sleep(0.01)
            value = self.value() + add
            self.setValue(value)
            if value > 50:
                self.change_color("green")
            if (not self._active or value >= self.maximum()):
                break
        self._active = False

    def closeEvent(self, event):
        self._active = False

    def change_color(self, color):
        template_css = """QProgressBar::chunk { background: %s; }"""
        css = template_css % color
        self.setStyleSheet(css)