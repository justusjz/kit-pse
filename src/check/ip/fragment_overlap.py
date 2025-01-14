from src.check.check import Check
from src.logger import Logger
from scapy.layers.inet import IP
from src.utils.fragment import FragmentChecker


class FragmentOverlap(Check):
    @classmethod
    def check(cls, packet):
        packet = packet[IP]
        frag_checker = FragmentChecker()
        src = packet[IP].src
        dst = packet[IP].dst
        frag_id = packet[IP].id
        # fragment size is measured in multiples of 8 octets
        frag_size = len(packet[IP].payload) / 8
        frag_offset = packet[IP].frag
        more_frags = "MF" in packet.flags
        if more_frags or frag_offset > 0:
            # this packet is fragmented, because either:
            # more fragments after this one
            # frag_offset > 0, so there were already fragments
            result = frag_checker.check(
                src, dst, frag_id, frag_size, frag_offset, more_frags
            )
            if result is not None:
                Logger.log_malicious_packet(packet, result)
