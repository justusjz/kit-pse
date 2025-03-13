import unittest
import main as main
from scapy.layers.inet import IP, TCP


class TestSignature(unittest.TestCase):
    def test_positive(self):
        with self.assertLogs() as log:
            pkt = IP(dst="127.0.0.1") / TCP(dport=7753)
            pkt.add_payload(b"SQL injection: ' OR")
            # TODO: do the checksum calculation somewhere else
            pkt[IP].chksum = IP(bytes(pkt[IP])).chksum
            pkt[TCP].chksum = TCP(bytes(pkt[TCP])).chksum
            main.packet_handler(pkt)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: SQL injection\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 7753"
                ],
            )
