from os import path
from pygtail import Pygtail
from PyQt4.QtGui import QListWidget,QMessageBox
from PyQt4.QtCore import SIGNAL,QTimer,QThread

class ThreadLogger(QThread):
    def __init__(self,logger_path=str):
        QThread.__init__(self)
        self.logger_path = logger_path
        self.started = False
    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.started =True
        while self.started:
            for line in Pygtail(self.logger_path):
                try:
                    self.emit(SIGNAL('Activated( QString )'),line.rstrip().split(' : ')[1])
                except IndexError:
                    pass

    def stop(self):
        self.started = False

class dockAreaAPI(QListWidget):
    def __init__(self, parent=None,info={}):
        super(dockAreaAPI, self).__init__(parent)
        self.setMinimumWidth(580)
        self.logger = info
        self.startThread  = False
        self.processThread = None

    def RunThread(self):
        self.startThread = True
        if self.logger != {}:
            self.processThread = ThreadLogger(self.logger['path'])
            self.connect(self.processThread,SIGNAL('Activated ( QString ) '), self.writeModeData)
            self.processThread.setObjectName(self.logger['thread_name'])
            if path.exists(self.logger['path']):
                self.processThread.start()
            if not self.processThread.isRunning():
                QMessageBox.warning(self,'error in read logger ',self.logger['error'])

    def writeModeData(self,data):
        self.addItem(data)
        self.scrollToBottom()

    def stopProcess(self):
        if self.processThread != None:
            self.processThread.stop()