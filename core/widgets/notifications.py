from PyQt4 import QtCore, QtGui
from core.utility.constants import NOTIFYSTYLE
"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for notifications in main tab.

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

class ServiceNotify(QtGui.QLabel):
    ''' notifications custom Qlabel widgets'''
    def __init__(self,text,title,link=None,timeout=None):
        QtGui.QLabel.__init__(self)
        self.link = link
        self.setAutoFillBackground(True)
        self.timeoutTimer = QtCore.QTimer(self)
        self.timeoutTimer.setSingleShot(True)
        self.effect = QtGui.QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.setText(self.decoretorText(text, title))

        # Fade in
        self.animationIn = QtCore.QPropertyAnimation(self.effect, 'opacity')
        self.animationIn.setDuration(300)
        self.animationIn.setStartValue(0)
        self.animationIn.setEndValue(1.0)

        # Fade out
        self.animationOut = QtCore.QPropertyAnimation(self.effect, 'opacity')
        self.animationOut.setDuration(300)
        self.animationOut.setStartValue(1.0)
        self.animationOut.setEndValue(0)
        if timeout is not None:
            self.timeoutTimer.setInterval(timeout)
            self.animationIn.finished.connect(self.timeoutTimer.start)
            self.timeoutTimer.timeout.connect(self.close)
        self.setstylelabel()
        self.linkActivated.connect(self.linkHandler)
        self.setFixedHeight(50)
        self.animationIn.start()

    def decoretorText(self,message, title, frmt='html'):
        ''' set html message and check if link is enable'''
        title = "<h5>%s<h5>" % title
        message = title + '{}'.format(message)
        if self.link != None:
            message += "<a href='{}'>DONATE</a>".format(self.link)
        return message

    def linkHandler(self, link):
        ''' go to link donate '''
        if not QtGui.QDesktopServices.openUrl(QtCore.QUrl(link)):
            QtGui.QMessageBox.warning(self, 'Open Url', 'Could not open url: {}'.format(link))

    def setstylelabel(self):
        ''' docorate label using stylesheet options '''
        self.setStyleSheet(NOTIFYSTYLE)

    def close(self):
        ''' start effect fade out on Label '''
        self.animationOut.finished.connect(super(ServiceNotify, self).close)
        self.animationOut.start()

