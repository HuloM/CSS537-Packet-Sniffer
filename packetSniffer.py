import binascii

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

packets = []
isActive = False
filter_string = ''


def pkt_sniffer():
    global isActive
    global packets

    def print_pkt(pkt):
        try:
            if pkt is not None and IP in pkt:
                sniffed_pkt = {'src_ip': pkt[IP].src,
                               'dst_ip': pkt[IP].dst,
                               'protocol': pkt[IP].proto}
                if TCP in pkt:
                    print("TCP")
                    sniffed_pkt['src_port'] = pkt[TCP].sport
                    sniffed_pkt['dst_port'] = pkt[TCP].dport
                    payload_data = pkt[TCP].payload
                elif UDP in pkt:
                    print("UDP")
                    sniffed_pkt['src_port'] = pkt[UDP].sport
                    sniffed_pkt['dst_port'] = pkt[UDP].dport
                    payload_data = pkt[UDP].payload
                else:
                    payload_data = None

                if payload_data:
                    sniffed_pkt['payload'] = payload_data.load.decode('UTF-8', 'ignore')
                packets.append(sniffed_pkt)
        except UnicodeEncodeError:
            print("Character encoding error")

    while isActive:
        # method to be able to stop and start sniffer as user requires
        sniff(count=10, prn=print_pkt, filter=filter_string)


# set whether sniffer is active or not
def set_active(active):
    global isActive
    isActive = active


# retrieve packets sniffed
def get_packets():
    global packets
    return packets.copy()


# when user receives packets already sniffed, dont want to resend old packets again
def clear_packets():
    global packets
    packets = []


# https://biot.com/capstats/bpf.html bpf filters used in scapy
def set_filters(data):
    global filter_string
    for key, value in data.items():
        if key == 'protocol':
            filter_string += value
        elif key == 'dst_ip':
            filter_string += ' and dst host ' + value
        elif key == 'dst_port':
            filter_string += ' and dst port ' + value
        elif key == 'src_ip':
            filter_string += ' and src host ' + value
        elif key == 'src_port':
            filter_string += ' and src port ' + value
