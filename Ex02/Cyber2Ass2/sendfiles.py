#!/usr/bin/python

# Question 6

# Receiving 3 arguments:
# 1) Path to the file to send
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

first = random.randint(0x00, 0x7f) + random.randint(0x00, 0x7f)
broadcast = "ffffffff" + `first`
bssid = "ffffffffffff"

filepath = sys.argv[1]
ssid = os.path.basename(filepath)
filesize = int(os.path.getsize(filepath))
pieces = filesize/255 + (filesize%255>0)
count = 1
print ssid

bssid = `pieces` + bssid[len(str(pieces)):12]
bssid = ":".join(bssid[i:i+2] for i in range(0,len(bssid),2))
print bssid

with open(filepath,"rb")as in_file:
	while count <= pieces:
		piece = in_file.read(255)
		print count
		broadcast = `count` + broadcast[len(str(count)):12]
		pkt = RadioTap() / Dot11(addr1 = bssid, addr2 = ":".join(broadcast[i:i+2] for i in range(0,len(broadcast),2)), addr3 = bssid) / Dot11Beacon(cap = 0x3114) / Dot11Elt( ID = 0, info = "[F]"+ssid) / Dot11Elt( ID = 1, info = piece) / Dot11Elt( ID = 3, info = "\x01") / Dot11Elt( ID = 5, info = "\x01\x03\x00\x08")
		sendp(pkt, iface = sys.argv[3], count = int(sys.argv[2]), inter = .2)
		count=count+1
