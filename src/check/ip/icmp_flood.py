from src.check.check import Check
from src.logger import Logger
from scapy.layers.inet import IP, ICMP
import time
from collections import defaultdict


class IcmpFlood(Check):
    __threshold = 100
    __timeinterval = 60
    __last_reset = time.time()
    __icmp_count = defaultdict(int)

    @classmethod
    def check(cls, packet):
        current_time = time.time()

        # Reset the ICMP count periodically
        if current_time - IcmpFlood.__last_reset > IcmpFlood.__timeinterval:
            IcmpFlood.__icmp_count.clear()
            IcmpFlood.__last_reset = current_time

        if ICMP in packet:
            src_ip = packet[IP].src
            IcmpFlood.__icmp_count[src_ip] += 1

            if IcmpFlood.__icmp_count[src_ip] > IcmpFlood.__threshold:
                Logger.log_malicious_packet(packet, "Potential ICMP flood detected.")
