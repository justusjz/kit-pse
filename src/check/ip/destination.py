from src.check.check import Check
from src.logger import Logger
from scapy.layers.inet import IP


class Destination(Check):
    @classmethod
    def check(cls, packet):
        dest_ip = packet[IP].dst
        if dest_ip.endswith(".0") or dest_ip.endswith(".255"):
            Logger.log_malicious_packet(
                packet, "Packets with broadcast destination address detected."
            )
