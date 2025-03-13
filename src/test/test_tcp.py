import unittest
import main as main
import time
from scapy.layers.inet import ICMP, IP, TCP
from src.test.test_utils import send_test_tcp_packet

from src.test.tcp import tcp_handshake_ignore


class TestTCP(unittest.TestCase):
    def test_handshake_negative(self):
        with self.assertNoLogs():
            send_test_tcp_packet(
                IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=44485, dport=80, flags="S")
            )
            send_test_tcp_packet(
                IP(
                    src="5.6.7.8",
                    dst="1.2.3.4",
                )
                / TCP(sport=80, dport=44485, flags="SA")
            )
            send_test_tcp_packet(
                IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=44485, dport=80, flags="A")
            )

    def test_handshake_positive(self):
        with self.assertLogs() as log:
            send_test_tcp_packet(
                IP(src="1.2.3.4", dst="9.10.11.12")
                / TCP(sport=44486, dport=80, flags="SA")
            )
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: Invalid TCP handshake flags "
                    "(expected S)\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 1.2.3.4, Destination IP: 9.10.11.12\n"
                    "Source Port: 44486, Destination Port: 80"
                ],
            )

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

    def test_xmas_scan(self):
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
                    "Source Port: 20, Destination Port: 80",
                ],
            )

    def test_malformed_packet_malformed_header(self):
        with self.assertLogs() as log:
            # we're not performing a valid TCP handshake here,
            # so we need to ignore that check for now
            tcp_handshake_ignore("127.0.0.1", "127.0.0.1", 20, 80)
            malformed_pkt = IP(dst="127.0.0.1", ihl=16, len=1000) / TCP(
                dport=80, dataofs=16
            )
            malformed_pkt[IP].chksum = IP(bytes(malformed_pkt[IP])).chksum
            malformed_pkt[TCP].chksum = TCP(bytes(malformed_pkt[TCP])).chksum
            main.packet_handler(malformed_pkt)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: Malformed packet detected. IP header "
                    "length is malformed.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80",
                    "WARNING:root:Malicious Packet Detected: Malformed packet detected. TCP "
                    "header length is malformed.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80",
                ],
            )

    def test_malformed_packet_malformed_length_and_protocol(self):
        with self.assertLogs() as log:
            malformed_pkt = IP(dst="127.0.0.1", ihl=5, len=7000, proto=255) / TCP(
                dport=80, dataofs=5
            )
            malformed_pkt[IP].chksum = IP(bytes(malformed_pkt[IP])).chksum
            malformed_pkt[TCP].chksum = TCP(bytes(malformed_pkt[TCP])).chksum
            main.packet_handler(malformed_pkt)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: Malformed packet detected. Total "
                    "length does not equal actual length.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80",
                    "WARNING:root:Malicious Packet Detected: Malformed packet detected. Protocol "
                    "number is reserved.\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 20, Destination Port: 80",
                ],
            )
