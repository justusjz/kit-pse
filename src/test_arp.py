import unittest
import main
from scapy.layers.all import ARP
from scapy.layers.inet import Ether


class TestSignature(unittest.TestCase):
    def test_negative(self):
        with self.assertNoLogs():
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op="is-at", hwsrc="60:b5:8d:8d:3e:7c", psrc="192.168.1.30"
            )
            main.packet_handler(pkt)
            main.packet_handler(pkt)

    def test_positive(self):
        with self.assertLogs() as log:
            pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op="is-at", hwsrc="60:b5:8d:8d:3e:7c", psrc="192.168.1.31"
            )
            main.packet_handler(pkt1)
            pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op="is-at", hwsrc="60:b5:8d:8d:3e:7d", psrc="192.168.1.31"
            )
            main.packet_handler(pkt2)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: ARP spoofing detected\n"
                    "MAC Address of malicious agent: 00:00:00:00:00:00\n"
                    "Source IP: N/A, Destination IP: N/A\n"
                    "Source Port: N/A, Destination Port: N/A"
                ],
            )
