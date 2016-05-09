#!/usr/bin/env python
from scapy.all import *
import sys
import getopt
import socket
from collections import deque
from time import ctime
import datetime


def main():

    interfaceFlag = 0
    fileFlag = 0
    expressionFlag = 0
    #interface = "ens33" #default interface
    try:
        opts, expressionList = getopt.getopt(sys.argv[1:], "i:r:")
    except getopt.GetoptError as err:
        print str(err)
        print "Usage: sudo python dnsdetect.py [-i interface] [-r tracefile] expression"
        sys.exit(2)

    for option, value in opts:
        if option == "-i":
            interfaceFlag = 1
            interface = value
        if option == "-r":
            fileFlag = 1
            fileName = value

    if (fileFlag and interfaceFlag):
        print "Error! -i option cannot be used with -r option!"
        sys.exit(2)
    if (fileFlag and expressionFlag):
        print "Error! Expression cannot be used with -r option!"
        sys.exit(2)

    if expressionList != []:
        expressionFlag = 1

    if fileFlag:
        #get the packets from the pcap file
        try:
            pktList = rdpcap(fileName)
        except Exception as err:
            print str(err)
            sys.exit(2)

        #print len(pktList)
        masterDNSpktList = []
        for pkt in pktList:
            DNSpktList = []
            rdataList = []
            if (pkt.haslayer(DNSRR)) and not(pkt.haslayer(ICMP)):
                DNSpktList.append(format(pkt.getlayer(DNS).id, '#04x'))
                DNSpktList.append(pkt.getlayer(DNS).qd.qname.rstrip("."))
                DNSframe = pkt['DNS']
                for i in xrange(DNSframe.ancount):
                    if DNSframe.an[i].type == 1 or DNSframe.an[i].type == 28:
                        rdataList.append(DNSframe.an[i].rdata)
                DNSpktList.append(rdataList)
                masterDNSpktList.append(DNSpktList)

        #The master list is ready. Find the attack
        #print masterDNSpktList
        for i in range(0, len(masterDNSpktList)-1):
            for j in range(i+1, len(masterDNSpktList)):
                if (masterDNSpktList[i][0] == masterDNSpktList[j][0]) and \
                        (masterDNSpktList[i][2] != masterDNSpktList[j][2]):
                    print
                    print
                    print "!!!!! ALERT !!!!!"
                    print ctime(), now.isoformat(), "DNS poisoning attempt!"
                    print "TXID:", masterDNSpktList[i][0], "Request:", masterDNSpktList[i][1]
                    print "Answer1:", masterDNSpktList[i][2]
                    print "Answer2:", masterDNSpktList[j][2]

    else: #Detect spoof packets by live capture

        #set the bpf filter
        expression = ''
        for exp in expressionList:
            expression = expression + " " + exp
        expression = expression.strip(" ")
        if (expressionFlag):
            bpfFilter = "src port 53 and " + "(" + expression + ")"
        else:
            bpfFilter = "src port 53"

        print "Detecting DNS poisoning..."
        masterDNSpktList = deque([])
        while (1):
            try:
                if interfaceFlag:
                    pktSniffed = sniff(iface = interface, filter = bpfFilter, count = 10)
                else:
                    pktSniffed = sniff(filter = bpfFilter, count = 10)
            except Exception as err:
                print str(err)
                sys.exit(2)
            for pkt in pktSniffed:
                DNSpktList = []
                rdataList = []
                if (pkt.haslayer(DNSRR)) and not(pkt.haslayer(ICMP)):
                    DNSpktList.append(format(pkt.getlayer(DNS).id, '#04x'))
                    DNSpktList.append(pkt.getlayer(DNS).qd.qname.rstrip("."))
                    DNSframe = pkt['DNS']
                    for i in xrange(DNSframe.ancount):
                        if DNSframe.an[i].type == 1 or DNSframe.an[i].type == 28:
                            rdataList.append(DNSframe.an[i].rdata)
                    DNSpktList.append(rdataList)
                    poisonFlag = 0
                    #Check if packet is a duplicate packet
                    if (len(masterDNSpktList) > 0):
                        for DNSpkt in masterDNSpktList:
                            if (DNSpktList[0] == DNSpkt[0]) and (DNSpktList[2] != DNSpkt[2]):
                                print
                                print
                                print "!!!!! ALERT !!!!!"
                                print "DNS poisoning attempt!"
                                print "TXID:", DNSpktList[0], "Request:", DNSpktList[1]
                                print "Answer1:", DNSpkt[2]
                                print "Answer2:", DNSpktList[2]
                                poisonFlag = 1
                                break
                        if (poisonFlag == 0):
                            if (len(masterDNSpktList) == 50):
                                masterDNSpktList.popleft()
                            masterDNSpktList.append(DNSpktList)
                    else:
                        masterDNSpktList.append(DNSpktList)

if __name__ == "__main__":
    main()