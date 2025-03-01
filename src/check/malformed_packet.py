from src.check.check import Check
from src.logging.logger import Logger
from scapy.layers.inet import IP, TCP


class MalformedPacket(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        maximum_header_length = 15
        minimum_header_length = 5
        if IP in packet:
            header_length = packet[IP].ihl
            total_length = packet[IP].len
            actual_length = len(packet[IP])
            maximum_length = 65535
            if header_length is None or total_length is None:
                pass
            elif (
                header_length > maximum_header_length
                or header_length < minimum_header_length
            ):
                Logger.log_malicious_packet(
                    packet, "Malformed packet detected. IP header length is malformed."
                )
            elif total_length > maximum_length:
                Logger.log_malicious_packet(
                    packet,
                    "Malformed packet detected. Total length exceeds maximum length.",
                )
            elif total_length != actual_length:
                Logger.log_malicious_packet(
                    packet,
                    "Malformed packet detected. Total length does not equal actual length.",
                )
            protocol_number = packet[IP].proto
            if protocol_number == 255:
                Logger.log_malicious_packet(
                    packet, "Malformed packet detected. Protocol number is reserved."
                )
        if TCP in packet:
            header_length = packet[TCP].dataofs
            if header_length is None:
                pass
            elif (
                header_length > maximum_header_length
                or header_length < minimum_header_length
            ):
                Logger.log_malicious_packet(
                    packet, "Malformed packet detected. TCP header length is malformed."
                )
