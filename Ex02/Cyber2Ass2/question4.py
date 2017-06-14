#!/usr/bin/env python

# Question 4

# Receiving 3 arguments:
# 1) The filter for the SSID
# 2) How many time to send the package
# 3) interface

import random
from scapy.all import *

def randomMAC():
	mac = [ 0x00, 0x16, 0x3e,
		random.randint(0x00, 0x7f),
		random.randint(0x00, 0xff),
		random.randint(0x00, 0xff) ]
	return ':'.join(map(lambda x: "%02x" % x, mac))

ap_list = []
fltr = sys.argv[1]

print "The filter is: %s" %(fltr)

def Broadcast(p) :
	broadcast = "ff:ff:ff:ff:ff:ff"
	bssid = randomMAC()

	pkt = RadioTap() / Dot11(addr1 = broadcast, addr2 = bssid, addr3 = bssid) / Dot11Beacon(cap = 0x3114) / Dot11Elt( ID = 0, info = p.info.replace(fltr,"[SENT]")) / Dot11Elt( ID = 1, info = "\x82\x84\x8b\x96\x0c\x12\x18\x24") / Dot11Elt( ID = 3, info = "\x01") / Dot11Elt( ID = 5, info = "\x01\x03\x00\x08")
	
	sendp(pkt, iface = sys.argv[3], count = int(sys.argv[2]), inter = .2)

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8 :
			if pkt.addr2 not in ap_list and fltr in pkt.info and "[SENT]" not in pkt.info :
				ap_list.append(pkt.addr2)
				print pkt.info
				Broadcast(pkt)

sniff(iface=sys.argv[3], prn = PacketHandler)

