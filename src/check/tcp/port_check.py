from src.check.check import Check
from src.logging.logger import Logger
from scapy.layers.inet import TCP


class PortCheck(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        if src_port == 0 or dst_port == 0:
            Logger.log_malicious_packet(
                packet, "Illegal packet with source or destination port 0."
            )
