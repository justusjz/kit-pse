from src.check.check import Check
from src.logger import Logger
from scapy.layers.inet import TCP
from src.utils import signature


class Signature(Check):
    __db = signature.SignatureDb("signatures.json")

    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        match = Signature.__db.detect(packet.__bytes__())
        if match is not None:
            Logger.log_malicious_packet(packet, match)
