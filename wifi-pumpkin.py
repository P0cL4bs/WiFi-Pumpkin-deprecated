#!/usr/bin/env python2.7
from sys import argv,exit
from os import getuid
from PyQt4.QtGui import QApplication,QIcon
from Core.Main import Initialize
from Core.loaders.checker.Privilege import frm_privelege
from Core.loaders.checker.check_depen import check_dependencies
from Core.Utils import Refactor,ExecRootApp

"""
Author : Marcos Nesster - mh4root@gmail.com  PocL4bs Team
Licence : GPL v3

Description:
    WiFi-Pumpkin - Framework for Rogue Wi-Fi Access Point Attack.

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


if __name__ == '__main__':
    check_dependencies()
    main = QApplication(argv)
    if not getuid() == 0:
        priv = frm_privelege()
        priv.setWindowIcon(QIcon('Icons/icon.ico'))
        priv.show(),main.exec_()
        exit(Refactor.threadRoot(priv.Editpassword.text()))
    ExecRootApp(Initialize,main)
