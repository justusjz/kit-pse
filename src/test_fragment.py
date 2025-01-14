from scapy.layers.inet import UDP, IP, ICMP, fragment
from scapy.packet import Packet
import unittest
import main
from test_utils import send_test_packet


class TestFragment(unittest.TestCase):
    def test_negative(self):
        with self.assertNoLogs():
            packet: Packet = (
                IP(src="13.14.15.16", dst="10.0.0.5") / ICMP() / ("X" * 6000)
            )
            packets = fragment(packet)
            for packet in packets:
                packet[IP].chksum = IP(packet[IP].__bytes__()).chksum
                main.packet_handler(packet)

    def test_positive(self):
        with self.assertLogs() as logs:
            src = "13.14.15.16"
            target = "10.0.0.5"
            # nestea attack, from https://scapy.readthedocs.io/en/latest/usage.html
            send_test_packet(
                IP(src=src, dst=target, id=42, flags="MF") / UDP() / ("X" * 10)
            )
            send_test_packet(IP(src=src, dst=target, id=42, frag=48) / ("X" * 116))
            send_test_packet(
                IP(src=src, dst=target, id=42, flags="MF") / UDP() / ("X" * 224)
            )
            self.assertEqual(
                logs.output,
                [
                    "WARNING:root:Malicious Packet Detected: Detected overlapping fragmented packet\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 13.14.15.16, Destination IP: 10.0.0.5\n"
                    "Source Port: 53, Destination Port: 53"
                ],
            )
