#!/usr/bin/env python

# Question 3

# Receiving 1 argument:
# 1) interface

from scapy.all import *

ap_list = []
iface = sys.argv[1]

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8 :
			if pkt.addr2 not in ap_list :
				ap_list.append(pkt.addr2)
				print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)
				p = pkt
				ssid,channel,crypto = None,None,None
				while Dot11Elt in p :
					p = p[Dot11Elt]
					if(p.ID == 0):
						ssid = p.info
					elif(p.ID == 1):
						print p.info
					elif(p.ID == 3):
						channel = ord(p.info)
					elif(p.ID == 48):
						crypto = "WPA2"
					elif(p.ID == 221 and crypto == None):
						crypto = "WPA"
					p=p.payload
				if not crypto :
					if "privacy" in  str(pkt.sprintf):
						crypto = "WEP"
					else:
						crypto = "OPN"
				print "SSID = %s , Channel = %s , Crypt = %s " %(ssid,channel,crypto)
				text_file = open("file_name.txt","a")
				text_file.write("Beacon Frame(BSSID: %s, SSID: %s, Channel: %s, Encryption: %s )" %(pkt.addr2, ssid,channel,crypto))
				text_file.write("\n")
				text_file.close()

sniff(iface=iface, prn = PacketHandler)

