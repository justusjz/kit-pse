from src.check.check import Check
from src.logger import Logger
from scapy.layers.inet import TCP


class Flag(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="FIN|RST")
        # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="SYN|RST")
        # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="FIN|PSH|URG")

        tcp_flags = packet[TCP].flags
        if "S" in tcp_flags and "F" in tcp_flags:
            Logger.log_malicious_packet(packet, "SYN-FIN combination.")
        elif "R" in tcp_flags and "F" in tcp_flags:
            Logger.log_malicious_packet(packet, "RST-FIN combination.")
        elif "S" in tcp_flags and "R" in tcp_flags:
            Logger.log_malicious_packet(packet, "RST-SYN combination.")
        elif "P" in tcp_flags and "F" in tcp_flags and "U" in tcp_flags:
            Logger.log_malicious_packet(packet, "XMAS combination.")
