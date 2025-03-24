from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP

from src.check.ip.ip_spoofing import IpSpoofing
from src.check.ip.destination import Destination
from src.check.ip.icmp_flood import IcmpFlood
from src.check.ip.fragment_overlap import FragmentOverlap
from src.check.tcp.connection import Connection
from src.check.tcp.flag import Flag
from src.check.tcp.null_packet import NullPacket
from src.check.tcp.port_check import PortCheck
from src.check.arp.arp_spoofing import ArpSpoofing
from src.check.signature import Signature
from src.check.checksum import Checksum
from src.check.dns_spoofing import DnsSpoofing
from src.check.malformed_packet import MalformedPacket
from src.check.udp.anomaly import UdpAnomaly


class Checker:
    def __init__(self):
        DnsSpoofing.update_malicious_ips()
        FragmentOverlap.init()
        self.ip_checks = [IpSpoofing, Destination, IcmpFlood, FragmentOverlap]
        self.udp_checks = [UdpAnomaly]
        self.tcp_checks = [Connection, Flag, NullPacket, PortCheck]

        self.arp_checks = [ArpSpoofing]

        self.checks = [Signature, Checksum, DnsSpoofing, MalformedPacket]

    def check(self, packet):
        if IP in packet:
            for ip_check in self.ip_checks:
                ip_check.check(packet)

        if TCP in packet:
            for tcp_check in self.tcp_checks:
                tcp_check.check(packet)

        if UDP in packet:
            for udp_check in self.udp_checks:
                udp_check.check(packet)

        if ARP in packet:
            for arp_check in self.arp_checks:
                arp_check.check(packet)

        for check in self.checks:
            check.check(packet)
