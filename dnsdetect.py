#! /usr/bin/env python
from scapy.all import *
import netifaces
import getopt
import socket
import datetime

changeToIp = netifaces.ifaddresses('eth0')[2][0]['addr']
interface = ""
filename = ""
BPFfilter = ""
recordTable = {}
fflag = 0

def arp_monitor_callback(pkt):
	ip = pkt['IP']
        udp = pkt['UDP']
	dns = pkt['DNS']
	responseList = []
	for i in range(dns.ancount):
		dnsrr = dns.an[i]
		responseList.append(dnsrr.rdata)
	if len(responseList) is 0:
		return
	if dns.id in recordTable:
		for ipans in responseList:
			if ipans not in recordTable[dns.id]:
				print datetime.datetime.now(), "\t", "DNS poisioning attempt"
				print "TXID ", hex(dns.id), " Request ", dnsrr.rrname
				print "Answer1 ", recordTable[dns.id]
				print "Answer2 ", dnsrr.rdata
				print '\n'
				return
	else:
		recordTable[dns.id] = responseList
	return
	
interfaces = netifaces.interfaces()
interface = interfaces[1]
opts, remainder = getopt.getopt(sys.argv[1:], "i:r:")

for opt, arg in opts:
	if opt in ('-i'):
		interface = arg
	elif opt in ('-r'):
		filename = arg

BPFfilter = " ".join(str(x) for x in remainder)

print "interface is ", interface

if len(filename) > 0:
	fflag = 1
	print "filename is ", filename

if len(BPFfilter) > 0: 
	print "BPFfilter is ", BPFfilter
	if "src port 53" in BPFfilter:
		print "Cannot enter src port 53 as a BPF filter"
		print "Please try again"
		exit()
if fflag is 0:
	sniff(iface=interface,prn=arp_monitor_callback, filter="src port 53", store=0)
else:
	sniff(offline=filename,prn=arp_monitor_callback, filter="src port 53", store=0)
	

