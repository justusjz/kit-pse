from src.check.check import Check
from src.logger import Logger
from scapy.layers.dns import DNS
import requests


class DnsSpoofing(Check):
    __malicious_ips = set([])

    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        if DNS in packet:
            dns_layer = packet[DNS]
            if dns_layer.qr == 1:  # qr = 1 means response

                for i in range(
                    dns_layer.ancount
                ):  # package can have multiple responses
                    dns_record = dns_layer.an[i]

                    if dns_record.type == 1:  # A record
                        answered_ip = dns_record.rdata
                        if answered_ip in DnsSpoofing.__malicious_ips:
                            Logger.log_malicious_packet(
                                packet,
                                f"Suspicious DNS response detected!\n"
                                f"Domain: {dns_record.rrname.decode(errors='ignore')}\n"
                                f"Malicious IP: {answered_ip}",
                            )

    @classmethod
    def update_malicious_ips(cls):
        DnsSpoofing.__malicious_ips.update(set(cls.__fetch_blocklist_ips()))

    @staticmethod
    def __fetch_blocklist_ips():
        """Fetches suspicious ips from blocklist.de from the last 12 hours,
        and returns them as a list"""
        url = "https://api.blocklist.de/getlast.php?time=00:00"
        try:
            Logger.log("Load IP-List from Blocklist.de....")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            ip_list = response.text.strip().split("\n")
            return ip_list
        except requests.RequestException as e:
            Logger.log_error(f"Failed fetching the Blocklist.de IPs: {e}")
            return []

    @classmethod
    def get_malicious_ips(cls):
        return cls.__malicious_ips
