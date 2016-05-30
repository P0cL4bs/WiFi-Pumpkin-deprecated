import argparse
import logging
import signal
import threading
from sys import stdout
from time import asctime
from os import path,stat,getpgid,setsid,killpg
from twisted.web import http
from twisted.internet import reactor
from Core.Utils import setup_logger
from subprocess import (Popen,PIPE,STDOUT)
from PyQt4.QtCore import QThread,pyqtSignal,SIGNAL
from Plugins.sergio_proxy.plugins import *
try:
    from nmap import PortScanner
except ImportError:
    pass

class ThreadPopen(QThread):
    def __init__(self,cmd):
        QThread.__init__(self)
        self.cmd = cmd
        self.process = None

    def getNameThread(self):
        return 'Starting Thread:' + self.objectName()

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT,close_fds=True)
        for line in iter(self.process.stdout.readline, b''):
            self.emit(SIGNAL('Activated( QString )'),line.rstrip())

    def stop(self):
        print 'Stop thread:' + self.objectName()
        if self.process is not None:
            self.process.terminate()
            self.process = None

class ThRunDhcp(QThread):
    ''' thread: run DHCP on background fuctions'''
    sendRequest = pyqtSignal(object)
    def __init__(self,args):
        QThread.__init__(self)
        self.args    = args
        self.process = None

    def getNameThread(self):
        return 'Starting Thread:' + self.objectName()

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.process = Popen(self.args,
        stdout=PIPE,stderr=STDOUT,preexec_fn=setsid)
        setup_logger('dhcp', './Logs/AccessPoint/dhcp.log')
        loggerDhcp = logging.getLogger('dhcp')
        loggerDhcp.info('---[ Start DHCP '+asctime()+']---')
        for line,data in enumerate(iter(self.process.stdout.readline, b'')):
            if 'DHCPREQUEST for' in data.rstrip():
                self.sendRequest.emit(data.split())
            elif 'DHCPACK on' in data.rstrip():
                self.sendRequest.emit(data.split())
            loggerDhcp.info(data.rstrip())

    def stop(self):
        print 'Stop thread:' + self.objectName()
        if self.process is not None:
            killpg(getpgid(self.process.pid), signal.SIGTERM)


class ThreadScan(QThread):
    def __init__(self,gateway):
        QThread.__init__(self)
        self.gateway = gateway
        self.result = ''
    def run(self):
        try:
            nm = PortScanner()
            a=nm.scan(hosts=self.gateway, arguments='-sU --script nbstat.nse -O -p137')
            for k,v in a['scan'].iteritems():
                if str(v['status']['state']) == 'up':
                    try:
                        ip = str(v['addresses']['ipv4'])
                        hostname = str(v['hostscript'][0]['output']).split(',')[0]
                        hostname = hostname.split(':')[1]
                        mac = str(v['hostscript'][0]['output']).split(',')[2]
                        if search('<unknown>',mac):mac = '<unknown>'
                        else:mac = mac[13:32]
                        self.result = ip +'|'+mac.replace('\n','')+'|'+hostname.replace('\n','')
                        self.emit(SIGNAL('Activated( QString )'),
                        self.result)
                    except :
                        pass
        except NameError:
            QMessageBox.information(self,'error module','the module Python-nmap not installed')



class ProcessThread(threading.Thread):
    def __init__(self,cmd,):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.iface = None
        self.process = None
        self.logger = False
        self.prompt = True

    def getNameThread(self):
        return 'Starting Thread:' + self.name

    def run(self):
        print 'Starting Thread:' + self.name
        if self.name == 'Dns2Proxy':
            setup_logger('dns2proxy', './Logs/AccessPoint/dns2proxy.log')
            log_dns2proxy = logging.getLogger('dns2proxy')
            self.logger = True
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT)
        for line in iter(self.process.stdout.readline, b''):
            if self.logger:
                if self.name == 'Dns2Proxy':
                    log_dns2proxy.info(line.rstrip())
                    self.prompt = False
            if self.prompt:
                print (line.rstrip())

    def stop(self):
        print 'Stop thread:' + self.name
        if self.process is not None:
            self.process.terminate()
            self.process = None


class ProcessHostapd(QThread):
    statusAP_connected = pyqtSignal(object)
    def __init__(self,cmd):
        QThread.__init__(self)
        self.cmd = cmd
        self.process= None

    def getNameThread(self):
        return 'Starting Thread:' + self.objectName()

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.makeLogger()
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT)
        for line in iter(self.process.stdout.readline, b''):
            #self.log_hostapd.info(line.rstrip())
            if self.objectName() == 'hostapd':
                if 'AP-STA-DISCONNECTED' in line.rstrip() or 'inactivity (timer DEAUTH/REMOVE)' in line.rstrip():
                    self.statusAP_connected.emit(line.split()[2])

    def makeLogger(self):
        setup_logger('hostapd', './Logs/AccessPoint/requestAP.log')
        self.log_hostapd = logging.getLogger('hostapd')

    def stop(self):
        print 'Stop thread:' + self.objectName()
        if self.process is not None:
            self.process.terminate()

class Thread_sslstrip(QThread):
    '''Thread: run sslstrip on brackground'''
    def __init__(self,port,plugins={},data= {}):
        QThread.__init__(self)
        self.port     = port
        self.plugins  = plugins
        self.loaderPlugins = data

    def getNameThread(self):
        return 'Starting Thread:' + self.objectName()

    def run(self):
        killSessions = True
        spoofFavicon = False
        listenPort   = self.port
        from Plugins.sslstrip.StrippingProxy import StrippingProxy
        from Plugins.sslstrip.URLMonitor import URLMonitor
        from Plugins.sslstrip.CookieCleaner import CookieCleaner
        print 'Starting Thread:' + self.objectName()
        print 'SSLstrip v0.9 by Moxie Marlinspike (@xtr4nge v0.9.2)::Online'
        print "+ POC by Leonardo Nve"
        if self.loaderPlugins['Plugins'] != None:
            self.plugins[self.loaderPlugins['Plugins']].getInstance()._activated = True
            self.plugins[self.loaderPlugins['Plugins']].getInstance().setInjectionCode(
                self.loaderPlugins['Content'])
        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)
        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy
        if not reactor.running:
            self.connector = reactor.listenTCP(int(listenPort), strippingFactory)
            try:
                reactor.run(installSignalHandlers=False)
            except Exception:
                pass
    def stop(self):
        print 'Stop thread:' + self.objectName()



class Thread_sergioProxy(QThread):
    '''Thread: run sergio-proxy on brackground'''
    def __init__(self,port,plugins={},options= {}):
        QThread.__init__(self)
        self.port          = port
        self.PumpPlugins   = plugins
        self.loaderPlugins = options

    def getNameThread(self):
        return 'Starting Thread:' + self.objectName()

    def run(self):
        killSessions = True
        spoofFavicon = False
        listenPort   = self.port
        sslstrip_version = "0.9"
        sergio_version = "0.2.1"
        if self.loaderPlugins['Plugins'] != None:
            self.PumpPlugins[self.loaderPlugins['Plugins']].getInstance()._activated = True
            self.PumpPlugins[self.loaderPlugins['Plugins']].getInstance().setInjectionCode(
                self.loaderPlugins['Content'])
        # load plugins will be implemented coming soon
        parser = argparse.ArgumentParser(
               description="Sergio Proxy v%s - An HTTP MITM Tool" % sergio_version,
               epilog="Use wisely, young Padawan.",
               fromfile_prefix_chars='@' )
        #add sslstrip options
        sgroup = parser.add_argument_group("sslstrip",
               "Options for sslstrip library")

        sgroup.add_argument("-w","--write",type=argparse.FileType('w'),
               metavar="filename", default=stdout,
               help="Specify file to log to (stdout by default).")
        sgroup.add_argument("--log-level",type=str,
               choices=['debug','info','warning','error'],default="info",
               help="Specify file to log to (stdout by default).")
        slogopts = sgroup.add_mutually_exclusive_group()
        slogopts.add_argument("-p","--post",action="store_true",
               help="Log only SSL POSTs. (default)")
        slogopts.add_argument("-s","--ssl",action="store_true",
               help="Log all SSL traffic to and from server.")
        slogopts.add_argument("-a","--all",action="store_true",
               help="Log all SSL and HTTP traffic to and from server.")
        sgroup.add_argument("-l","--listen",type=int,metavar="port",default=10000,
               help="Port to listen on (default 10000)")
        sgroup.add_argument("-f","--favicon",action="store_true",
                help="Substitute a lock favicon on secure requests.")
        sgroup.add_argument("-k","--killsessions",action="store_true",
                help="Kill sessions in progress.")

        #add msf options
        sgroup = parser.add_argument_group("MSF",
                "Generic Options for MSF integration")

        sgroup.add_argument("--msf-path",type=str,default="/pentest/exploits/framework/",
                help="Path to msf (default: /pentest/exploits/framework)")
        sgroup.add_argument("--msf-rc",type=str,default="/tmp/tmp.rc",
                help="Specify a custom rc file (overrides all other settings)")
        sgroup.add_argument("--msf-user",type=str,default="root",
                help="Specify what user to run Metasploit under.")
        sgroup.add_argument("--msf-lhost",type=str,default="192.168.1.1",
                help="The IP address Metasploit is listening at.")

        plugin_classes = plugin.Plugin.__subclasses__()
        #Initialize plugins
        plugins = []
        try:
            for p in plugin_classes:
                plugins.append(p())
        except:
            print "Failed to load plugin class %s" % str(p)

        #Give subgroup to each plugin with options
        try:
            for p in plugins:
                if p.desc == "":
                    sgroup = parser.add_argument_group("%s" % p.name,
                        "Options for %s." % p.name)
                else:
                    sgroup = parser.add_argument_group("%s" % p.name,
                        p.desc)

                sgroup.add_argument("--%s" % p.optname, action="store_true",
                        help="Load plugin %s" % p.name)
                if p.has_opts:
                    p.add_options(sgroup)
        except NotImplementedError:
            print "Plugin %s claimed option support, but didn't have it." % p.name

        args = parser.parse_args()
        if args.msf_rc == "/tmp/tmp.rc":
            #need to wipe
            open(args.msf_rc,"w").close()
        args.full_path = path.dirname(path.abspath(__file__))

        #All our options should be loaded now, pass them onto plugins
        load = []
        try:
            for p in plugins:
                if  getattr(args,p.optname):
                    p.initialize(args)
                    load.append(p)
        except NotImplementedError:
            print "Plugin %s lacked initialize function." % p.name

        #this whole msf loading process sucks. need to improve
        if args.msf_rc != "/tmp/tmp.rc" or stat("/tmp/tmp.rc").st_size != 0:
            from Plugins.sergio_proxy.plugins.StartMSF import launch_msf
            launch_msf(args.msf_path,args.msf_rc,args.msf_user)

        from Plugins.sergio_proxy.sslstrip.StrippingProxy import StrippingProxy
        from Plugins.sergio_proxy.sslstrip.URLMonitor import URLMonitor
        from Plugins.sergio_proxy.sslstrip.CookieCleaner import CookieCleaner

        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)
        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy
        print 'Starting Thread:' + self.objectName()
        print "\nsslstrip " + sslstrip_version + " by Moxie Marlinspike running..."
        print "sergio-proxy v%s online" % sergio_version
        if not reactor.running:
            self.connector = reactor.listenTCP(int(listenPort), strippingFactory)
            try:
                reactor.run(installSignalHandlers=False)
            except Exception:
                pass

    def stop(self):
        print 'Stop thread:' + self.objectName()
