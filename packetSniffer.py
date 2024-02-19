from scapy.all import *


def print_pkt(pkt):
    try:
        print(pkt.show(dump=True))
    except UnicodeEncodeError:
        print("Character encoding error")


t = AsyncSniffer(prn=print_pkt)


def start_scan():
    t.start()


def stop_scan():
    t.stop()
