#!/usr/bin/env python

# Question 6

# Receiving 1 argument:
# 1) interface

from scapy.all import *

ap_list = []
iface = sys.argv[1]
os.chdir(os.path.dirname(__file__))
directory = os.getcwd()+"/Downloads/"

if not os.path.exists(directory) :
	os.makedirs(directory)

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8 :
			if pkt.addr2 not in ap_list and "[F]" in pkt.info :
				ap_list.append(pkt.addr2)
				p = pkt
				filename = p.info.replace("[F]","")
				content = None
				while Dot11Elt in p :
					p = p[Dot11Elt]
					if(p.ID == 0):
						ssid = p.info
					elif(p.ID == 1):
						content = p.info
					p=p.payload
				text_file = open(directory+filename,"a")
				text_file.write(content)
				text_file.close()

sniff(iface=iface, prn = PacketHandler)
print "end"

