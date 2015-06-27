from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Modules.connection import *
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
class frm_datebase(QDialog):
    def __init__(self, parent=None):
        super(frm_datebase, self).__init__(parent)
        self.setWindowTitle("DataBase Manager")
        self.setWindowIcon(QIcon('rsc/icon.ico'))
        sshFile="Core/dark_style.css"
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())
        self.Main = QVBoxLayout()
        self.control = None
        create_tables()
        self.GUI()
    def GUI(self):
        self.form = QFormLayout(self)
        self.list_db = QListWidget(self)
        self.grid = QGridLayout(self)

        self.rb_face = QRadioButton("Facebook")
        self.rb_gmail = QRadioButton("Gmail")
        self.rb_route = QRadioButton("Route")
        self.btn_save = QPushButton("Export Credentials...")
        self.input_delete = QLineEdit(self)
        self.input_delete.setFixedWidth(300)
        self.btn_delete = QPushButton("Delete")
        self.btn_gettables = QPushButton("Show Data")
        self.btn_exit = QPushButton("Close")
        self.delete_all = QPushButton("Delete All")
        self.btn_delete.clicked.connect(self.delete_db)
        self.btn_gettables.clicked.connect(self.get_rows)
        self.list_db.clicked.connect(self.list_clicked)
        self.delete_all.clicked.connect(self.db_all)
        self.btn_save.clicked.connect(self.save_fuc)
        self.btn_exit.clicked.connect(self.close)
        self.grid.addWidget(self.rb_face, 0,0)
        self.grid.addWidget(self.rb_gmail, 0,1)
        self.grid.addWidget(self.rb_route, 0,2)
        self.grid.addWidget(self.btn_gettables, 1,0)
        self.grid.addWidget(self.btn_save, 1,4)
        self.grid.addWidget(self.btn_exit, 1,3)

        self.form.addRow(self.list_db)
        self.form.addRow(self.input_delete,self.btn_delete)
        self.form.addRow(self.delete_all)
        self.form.addRow(self.grid)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def db_all(self):
        if self.rb_face.isChecked():
            delete_db_all(100, "Facebook")
            self.input_delete.clear()
            self.get_rows()
        elif self.rb_gmail.isChecked():
            delete_db_all(100, "Gmail")
            self.input_delete.clear()
            self.get_rows()
        elif self.rb_route.isChecked():
            delete_db_all(100, "Route")
            self.input_delete.clear()
            self.get_rows()

    def delete_db(self):
        if len(self.input_delete.text()) > 0:
            n = str(self.input_delete.text())
            n = n.split()
            n = n[0]
            if self.rb_face.isChecked():
                status = delete_one("Facebook",n[3:])
                QMessageBox.information(self, 'Facebook db Info', status)
                self.get_rows()
                self.input_delete.clear()
            elif self.rb_gmail.isChecked():
                status = delete_one("Gmail",n[3:])
                QMessageBox.information(self, 'Gmail db Info', status)
                self.get_rows()
                self.input_delete.clear()
            elif self.rb_route.isChecked():
                status = delete_one("Route",n[3:])
                QMessageBox.information(self, 'Route db Info', status)
                self.get_rows()
                self.input_delete.clear()
        else:
            QMessageBox.information(self,"Select db", "Please, select the row to delete db")
    def get_rows(self):
        self.list_db.clear()
        if self.rb_face.isChecked():
            cursor = c.execute("SELECT id,email,password,datestamp FROM Facebook")
            for row in cursor:
                self.list_db.addItem("ID:" + str(row[0]) + " Email: " + str(row[1]) + "  Password:"  + str(row[2]) + " | " + str(row[3]) + "|")
        elif self.rb_gmail.isChecked():
            cursor = c.execute("SELECT id,email,password,datestamp FROM Gmail")
            for row in cursor:
                self.list_db.addItem("ID:" + str(row[0]) + " Email: " + str(row[1]) + "  Password:"  + str(row[2]) + " | " + str(row[3]) + "|")
        elif self.rb_route.isChecked():
            cursor = c.execute("SELECT id,ipaddress,password,datestamp FROM Route")
            for row in cursor:
                self.list_db.addItem("ID:" + str(row[0]) + " IPaddress: " + str(row[1] + "| Password:" +  str(row[2])))

    @pyqtSlot(QModelIndex)
    def list_clicked(self, index):
        itms = self.list_db.selectedIndexes()
        for i in itms:
            self.input_delete.setText(i.data().toString())

    def save_fuc(self):
        if self.list_db.count() > 0:
            file = QFileDialog()
            output= file.getSaveFileName(self, "Export database credentials...", "passwords.txt")
            if len(output) > 0:
                f_pass = open(output, "a")
                for i in range(self.list_db.count()):
                    f_pass.write(str(self.list_db.item(i).text()+"\n"))
                    f_pass.write("------------------------------------------------------\n")
                f_pass.close()
                QMessageBox.information(self, "Expoted credentials", "Export database credentials with success...")
