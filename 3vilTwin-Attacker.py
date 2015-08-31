#!/usr/bin/env python2.7
#The MIT License (MIT)
#Copyright (c) 2015-2016 mh4x0f P0cL4bs Team
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in
#the Software without restriction, including without limitation the rights to
#use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
#the Software, and to permit persons to whom the Software is furnished to do so,
#subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
#FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
from sys import argv,exit
from os import getuid
from PyQt4.QtGui import QApplication,QIcon
from Core.Privilege import frm_privelege
from Core.Main import Initialize
from Core.check import check_dependencies
from Modules.utils import Refactor

def ExecRootApp():
    check_dependencies()
    root = QApplication(argv)
    app = Initialize()
    app.setWindowIcon(QIcon('rsc/icon.ico'))
    app.center(),app.show()
    exit(root.exec_())

if __name__ == '__main__':
    if not getuid() == 0:
        app2 = QApplication(argv)
        priv = frm_privelege()
        priv.setWindowIcon(QIcon('rsc/icon.ico'))
        priv.show(),app2.exec_()
        exit(Refactor.threadRoot(priv.Editpassword.text()))
    ExecRootApp()