from src.check.check import Check
from src.logger import Logger
from scapy.layers.inet import IP


class IpSpoofing(Check):
    __reserved_ips = ["192.168.1.4", "192.168.1.1", "192.168.1.7", "172.16.0.3"]

    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        src_ip = packet[IP].src
        if src_ip not in IpSpoofing.__reserved_ips:
            if (
                src_ip.startswith("10.")
                or src_ip.startswith("192.168.")
                or src_ip.startswith("169.254.")
            ):
                Logger.log_malicious_packet(
                    packet, "Possible IP spoofing using private networks detected."
                )

            elif src_ip.startswith("172."):
                octet = int(src_ip.split(".")[1])
                if 16 <= octet <= 31:
                    Logger.log_malicious_packet(
                        packet, "Possible IP spoofing using private networks detected."
                    )
