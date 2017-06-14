#!/usr/bin/python

# Question 1

# Receiving 3 arguments:
# 1) The SSID
# 2) How many time to send the package
# 3) interface

import sys
import random
from scapy.all import *

def randomMAC():
	mac = [ random.randint(0x00, 0x7f),
		random.randint(0x00, 0x7f),
		random.randint(0x00, 0x7f),
		random.randint(0x00, 0x7f),
		random.randint(0x00, 0xff),
		random.randint(0x00, 0xff) ]
	return ':'.join(map(lambda x: "%02x" % x, mac))

broadcast = "ff:ff:ff:ff:ff:ff"
bssid = randomMAC()
print bssid
print len(sys.argv[1])

pkt = RadioTap() / Dot11(addr1 = broadcast, addr2 = bssid, addr3 = bssid) / Dot11Beacon(cap = 0x3114) / Dot11Elt( ID = 0, info = sys.argv[1]) / Dot11Elt( ID = 1, info = "\x82\x84\x8b\x96\x0c\x12\x18\x24") / Dot11Elt( ID = 3, info = "\x01") / Dot11Elt( ID = 5, info = "\x01\x03\x00\x08")

sendp(pkt, iface = sys.argv[3], count = int(sys.argv[2]), inter = .2)
