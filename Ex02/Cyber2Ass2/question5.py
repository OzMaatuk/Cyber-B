#!/usr/bin/python

# Question 5

# Receiving 4 arguments:
# 1) SSID - the title
# 2) Rates - the content
# 3) How many time to send the package
# 4) interface

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

ssid = sys.argv[1]
#ssid = [:29]
rates = sys.argv[2]
rates = rates[:255]

pkt = RadioTap() / Dot11(addr1 = broadcast, addr2 = bssid, addr3 = bssid) / Dot11Beacon(cap = 0x3114) / Dot11Elt( ID = 0, info = ssid) / Dot11Elt( ID = 1, info = rates) / Dot11Elt( ID = 3, info = "\x01") / Dot11Elt( ID = 5, info = "\x01\x03\x00\x08")

sendp(pkt, iface = sys.argv[4], count = int(sys.argv[3]), inter = .2)
