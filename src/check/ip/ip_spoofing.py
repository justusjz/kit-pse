from src.check.check import Check
from src.logging.logger import Logger
from scapy.layers.inet import IP
from src.conf import CHECK_IP_SPOOFING, RESERVED_IPS


class IpSpoofing(Check):
    __reserved_ips = RESERVED_IPS

    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        src_ip = packet[IP].src
        if src_ip not in IpSpoofing.__reserved_ips and CHECK_IP_SPOOFING:
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
