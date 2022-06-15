#!/usr/bin/env python
import scapy.all as scapy 
# import optparse 
import argparse
import re 

def get_arguments():
    parser = argparse.ArgumentParser() 
    parser.add_argument("-t", "--target" ,dest="target" , help="Put your ip address")
    (options) = parser.parse_args()
    # store the options(values) and args in tow var 
    return options

def scan(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # print(arp_request_broadcast.summary())
    # arp_request_broadcast.show()
    # answered_list , unanswered = scapy.srp(arp_request_broadcast , timeout=2)# we used srp instead of sr , because we used custom Ether(ff....)
    answered_list = scapy.srp(arp_request_broadcast , timeout=1 , verbose=False)[0]
    # print(answered_list.summary())
    client_lists = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc , "mac": element[1].hwsrc }
        client_lists.append(client_dict)
        # print(element[1].psrs + "\t\t" + element[1].hwsrc)  
        # print(unanswered.summary())
        # print(broadcast.summary())
        # print(arp_request.summary())
        # scapy.ls(scapy.ARP()) list all fields that we can to set on ARP
        # scapy.ls(scapy.Ether()) list all fields that we can to set on Ether
    return client_lists

def print_result(results_list):
    print("IP \t\t\t MAC ADDRESS \n------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client['mac'] )


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

# ip of the source 
# mac address of the source