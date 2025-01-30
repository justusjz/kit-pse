from src.check.check import Check
from src.logger import Logger
from scapy.layers.inet import TCP


class NullPacket(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        tcp_flags = packet[TCP].flags
        if tcp_flags == 0:
            Logger.log_malicious_packet(packet, "Malicious null packet found.")
