import unittest
import main as main
from src.check.dns_spoofing import DnsSpoofing
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import socket


class TestDnsSpoofing(unittest.TestCase):
    def test_malicious_dns_response(self):
        DnsSpoofing.update_malicious_ips()
        with self.assertLogs() as log:
            ips = iter(DnsSpoofing.get_malicious_ips())
            while True:
                try:
                    # get the next IP address, and check whether its valid
                    malicious_ip = next(ips)
                    socket.inet_aton(malicious_ip)
                    break
                except:
                    # repeat until we get a good one
                    pass
            dns_response_packet = (
                IP(src="127.0.0.1", dst="127.0.0.1")
                / UDP(sport=53, dport=7753)
                / DNS(
                    id=0xAAAA,
                    qr=1,
                    aa=1,
                    qdcount=1,
                    ancount=1,
                    qd=DNSQR(qname="malicious.com", qtype="A"),
                    an=DNSRR(
                        rrname="malicious.com", type="A", ttl=60, rdata=malicious_ip
                    ),
                )
            )
            dns_response_packet[IP].chksum = IP(bytes(dns_response_packet[IP])).chksum
            dns_response_packet[UDP].chksum = UDP(
                bytes(dns_response_packet[UDP])
            ).chksum
            main.packet_handler(dns_response_packet)
            self.assertEqual(
                log.output,
                [
                    "WARNING:root:Malicious Packet Detected: Suspicious DNS response detected!\n"
                    "Domain: malicious.com.\n"
                    f"Malicious IP: {malicious_ip}\n"
                    "MAC Address of malicious agent: N/A\n"
                    "Source IP: 127.0.0.1, Destination IP: 127.0.0.1\n"
                    "Source Port: 53, Destination Port: 7753"
                ],
            )
