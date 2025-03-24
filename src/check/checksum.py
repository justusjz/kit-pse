from src.check.check import Check
from src.logging.logger import Logger
from scapy.layers.inet import IP, TCP


class Checksum(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        if IP in packet:
            # packet = IP(dst="10.11.12.13", src="10.11.12.14")/UDP(chksum=0)/DNS()
            original_checksum = packet[
                IP
            ].chksum  # saves original checksum for comparison
            del packet[IP].chksum  # deletes the current checksum
            recalculated_checksum = IP(
                bytes(packet[IP])
            ).chksum  # Scapy recalculates the checksum
            if original_checksum != recalculated_checksum:
                Logger.log_malicious_packet(packet, "Invalid IP checksum.")

        if IP in packet and TCP in packet:
            # TODO: this does not work correctly for IPv6,
            # so we restrict it to IP for now
            original_checksum = packet[
                TCP
            ].chksum  # saves original checksum for comparison
            del packet[TCP].chksum  # deletes the current checksum
            recalculated_checksum = TCP(
                bytes(packet[TCP])
            ).chksum  # Scapy recalculates the checksum
            if original_checksum != recalculated_checksum:
                Logger.log_malicious_packet(packet, "Invalid TCP checksum.")
