from src.check.check import Check
from src.logger import Logger
from scapy.layers.l2 import ARP


class ArpSpoofing(Check):
    __arp_table = dict()

    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        if packet[ARP].op == 2:
            mac = packet[ARP].hwsrc
            ip = packet[ARP].psrc
            if ip in ArpSpoofing.__arp_table:
                old_mac = ArpSpoofing.__arp_table[ip]
                if old_mac != mac:
                    # different MAC than before
                    Logger.log_malicious_packet(packet, "ARP spoofing detected")
            else:
                # previously unknown IP
                ArpSpoofing.__arp_table[ip] = mac
