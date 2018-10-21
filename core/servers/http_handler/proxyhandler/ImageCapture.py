from collections import OrderedDict

from core.main import  QtGui,QtCore
from core.servers.http_handler.proxyhandler.MitmMode import MitmMode


class ImageCapture(MitmMode):
    Name = "Image Capture"
    ID = "ImageCapture"
    Author = "Pumpkin-Dev"
    Description = "Capture Image Sniffed from the connection"
    Icon = "icons/image.png"
    ModSettings = True
    Hidden = False
    ModType = "proxy"  # proxy or server
    def __init__(self,parent,FSettingsUI=None,main_method=None,  **kwargs):
        super(ImageCapture, self).__init__(parent)
        self.mainLayout     = QtGui.QVBoxLayout()
        self.main_method    = main_method
        #scroll area
        self.scrollwidget = QtGui.QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QtGui.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)
        self.imagesList = []

        self.THUMBNAIL_SIZE = 146
        self.SPACING = 8
        self.IMAGES_PER_ROW = 4
        self.TableImage = QtGui.QTableWidget()
        self.TableImage.setIconSize(QtCore.QSize(146, 146))
        self.TableImage.setColumnCount(self.IMAGES_PER_ROW)
        self.TableImage.setGridStyle(QtCore.Qt.NoPen)

        self.TableImage.verticalHeader().setDefaultSectionSize(self.THUMBNAIL_SIZE + self.SPACING)
        self.TableImage.verticalHeader().hide()
        self.TableImage.horizontalHeader().setDefaultSectionSize(self.THUMBNAIL_SIZE + self.SPACING)
        self.TableImage.horizontalHeader().hide()

        self.TableImage.setMinimumWidth((self.THUMBNAIL_SIZE + self.SPACING) * self.IMAGES_PER_ROW + (self.SPACING * 2))
        self.imageListPath  = OrderedDict([ ('Path',[])])
        self.mainLayout.addWidget(self.TableImage)
        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.setLayout(self.layout)

    def SendImageTableWidgets(self,image):
        self.imageListPath['Path'].append(image)
        rowCount = len(self.imageListPath['Path']) // self.IMAGES_PER_ROW
        if len(self.imageListPath['Path']) % self.IMAGES_PER_ROW: rowCount += 1
        self.TableImage.setRowCount(rowCount)
        row = -1
        for i, picture in enumerate(self.imageListPath['Path']):
            col = i % self.IMAGES_PER_ROW
            if not col: row += 1
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

