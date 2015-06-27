#! /usr/bin/python
from sys import argv
from PyQt4.QtGui import *
from Core.Main import frmControl
from Core.check import check_dependencies
if __name__ == '__main__':
    check_dependencies()
    root = QApplication(argv)
    app = frmControl(None)
    app.setWindowIcon(QIcon('rsc/icon.ico'))
    app.center()
    app.show()
    root.exec_()