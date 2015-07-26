#!/usr/bin/env python2.7
from sys import argv
from PyQt4.QtGui import *
from Core.Main import Initialize
from Core.check import check_dependencies
if __name__ == '__main__':
    check_dependencies()
    root = QApplication(argv)
    app = Initialize(None)
    app.setWindowIcon(QIcon('rsc/icon.ico'))
    app.center()
    app.show()
    root.exec_()