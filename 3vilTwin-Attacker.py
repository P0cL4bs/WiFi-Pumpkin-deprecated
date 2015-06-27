#! /usr/bin/python
from sys import argv,exit
from os import getuid
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.check_privilege import frm_privelege
from Core.Main import frmControl
from Core.check import check_dependencies
if __name__ == '__main__':
    if not getuid() == 0:
        app2 = QApplication(argv)
        priv = frm_privelege()
        priv.setWindowIcon(QIcon('rsc/icon.ico'))
        priv.setWindowFlags(priv.windowFlags() | Qt.WindowMaximizeButtonHint)
        priv.show()
        exit(app2.exec_())
    else:
        check_dependencies()
        root = QApplication(argv)
        app = frmControl(None)
        app.setWindowIcon(QIcon('rsc/icon.ico'))
        app.center()
        app.show()
        root.exec_()


