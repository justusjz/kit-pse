import unittest
import main
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR


class TestDnsSpoofing(unittest.TestCase):
    def test_malicious_dns_response(self):
        with self.assertLogs() as log:
            main.malicious_ips.update(main.fetch_blocklist_ips())

            if main.malicious_ips:
                malicious_ip = next(iter(main.malicious_ips))
            else:
                malicious_ip = "10.10.10.10"
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
