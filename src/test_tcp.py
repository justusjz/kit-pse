import unittest
import main
import time
from scapy.layers.inet import ICMP, IP, TCP


class TestTCP(unittest.TestCase):
    def test_null(self):
        with self.assertLogs() as log:
            null_pkt = IP(dst="127.0.0.1") / TCP(dport=80, flags=0)
            null_pkt[IP].chksum = IP(bytes(null_pkt[IP])).chksum
            null_pkt[TCP].chksum = TCP(bytes(null_pkt[TCP])).chksum
            main.packet_handler(null_pkt)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: Malicious null packet found.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80"
                ],
            )

    def test_icmp_flood(self):
        with self.assertLogs() as log:
            icmp_pkt = IP(dst="127.0.0.1") / ICMP()
            for i in range(101):
                icmp_pkt[IP].chksum = IP(bytes(icmp_pkt[IP])).chksum
                main.packet_handler(icmp_pkt)
                time.sleep(0.001)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: Potential ICMP flood detected.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: N/A, Destination Port: N/A"
                ],
            )

    def test_syn_fin(self):
        with self.assertLogs() as log:
            syn_fin_pkt = IP(dst="127.0.0.1") / TCP(dport=80, flags="FS")
            syn_fin_pkt[IP].chksum = IP(bytes(syn_fin_pkt[IP])).chksum
            syn_fin_pkt[TCP].chksum = TCP(bytes(syn_fin_pkt[TCP])).chksum
            main.packet_handler(syn_fin_pkt)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: SYN-FIN combination.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80"
                ],
            )

    def test_xmas(self):
        with self.assertLogs() as log:
            xmas_pkt = IP(dst="127.0.0.1") / TCP(dport=80, flags="FPU")
            xmas_pkt[IP].chksum = IP(bytes(xmas_pkt[IP])).chksum
            xmas_pkt[TCP].chksum = TCP(bytes(xmas_pkt[TCP])).chksum
            main.packet_handler(xmas_pkt)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: XMAS combination.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80"
                ],
            )

    def test_checksum(self):
        with self.assertLogs() as log:
            chksum_pkt = IP(dst="127.0.0.1", chksum=0) / TCP(dport=80, chksum=0)
            main.packet_handler(chksum_pkt)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: Invalid IP checksum.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80",
                    "WARNING:root:Malicious Packet Detected: Invalid TCP checksum.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80"
                ],
            )