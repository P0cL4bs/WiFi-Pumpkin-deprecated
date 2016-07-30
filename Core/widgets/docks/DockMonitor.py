from os import path
from PyQt4.QtGui import QListWidget,QMessageBox
from PyQt4.QtCore import SIGNAL,QTimer,QThread,QProcess,pyqtSlot,QObject,SLOT

class ThreadLogger(QObject):
    def __init__(self,logger_path=str):
        QObject.__init__(self)
        self.logger_path = logger_path

    @pyqtSlot()
    def readProcessOutput(self):
        try:
            self.emit(SIGNAL('Activated( QString )'),
            str(self.procLogger.readAllStandardOutput()).rstrip().split(' : ')[1])
        except Exception: pass

    def start(self):
        self.procLogger = QProcess(self)
        self.procLogger.setProcessChannelMode(QProcess.MergedChannels)
        QObject.connect(self.procLogger, SIGNAL('readyReadStandardOutput()'), self, SLOT('readProcessOutput()'))
        self.procLogger.start('tail',['-f',self.logger_path])

    def stop(self):
        if hasattr(self,'procLogger'):
            self.procLogger.terminate()
            self.procLogger.waitForFinished()
            self.procLogger.kill()

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
    def writeModeData(self,data):
        self.addItem(data)
        self.scrollToBottom()

    def stopProcess(self):
        if self.processThread != None:
            self.processThread.stop()