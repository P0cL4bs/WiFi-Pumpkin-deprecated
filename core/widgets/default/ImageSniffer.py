from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.Qt import *
from core.widgets.default.uimodel import *


class ImageSniffer(TabsWidget):
    Name = "Sniffer Image"
    ID = "ImageSniffer"
    Icon = "icons/image.png"
    __subitem = False
    sendError = QtCore.pyqtSignal(str)

    def __init__(self, parent=None, FSettings=None):
        super(ImageSniffer, self).__init__(parent, FSettings)
        self.imagesList = []
        self.THUMBNAIL_SIZE = 146
        self.SPACING = 8
        self.IMAGES_PER_ROW = 4
        self.TableImage = QtGui.QTableWidget()
        self.TableImage.setIconSize(QtCore.QSize(146, 146))
        self.TableImage.setColumnCount(self.IMAGES_PER_ROW)
        self.TableImage.setGridStyle(QtCore.Qt.NoPen)

        self.TableImage.verticalHeader().setDefaultSectionSize(
            self.THUMBNAIL_SIZE + self.SPACING)
        self.TableImage.verticalHeader().hide()
        self.TableImage.horizontalHeader().setDefaultSectionSize(
            self.THUMBNAIL_SIZE + self.SPACING)
        self.TableImage.horizontalHeader().hide()

        self.TableImage.setMinimumWidth(
            (self.THUMBNAIL_SIZE + self.SPACING) * self.IMAGES_PER_ROW + (self.SPACING * 2))
        self.imageListPath = OrderedDict([('Path', [])])
        self.scroll.setWidget(self.TableImage)

    def SendImageTableWidgets(self, image):
        self.imageListPath['Path'].append(image)
        rowCount = len(self.imageListPath['Path']) // self.IMAGES_PER_ROW
        if len(self.imageListPath['Path']) % self.IMAGES_PER_ROW:
            rowCount += 1
        self.TableImage.setRowCount(rowCount)
        row = -1
        for i, picture in enumerate(self.imageListPath['Path']):
            col = i % self.IMAGES_PER_ROW
            if not col:
                row += 1
            self.addPicture(row, col, picture)

    def addPicture(self, row, col, picturePath):
        item = QtGui.QTableWidgetItem()
        p = QtGui.QPixmap(picturePath)
        if not p.isNull():
            if p.height() > p.width():
                p = p.scaledToWidth(self.THUMBNAIL_SIZE)
            else:
                p = p.scaledToHeight(self.THUMBNAIL_SIZE)
            p = p.copy(0, 0, self.THUMBNAIL_SIZE, self.THUMBNAIL_SIZE)
            item.setIcon(QtGui.QIcon(p))
            self.TableImage.setItem(row, col, item)
            self.TableImage.scrollToBottom()
