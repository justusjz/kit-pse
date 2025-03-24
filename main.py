from src.checker import Checker
from scapy.all import sniff
from src.logging.logger import Logger
from src.conf import SNIFF_FILTER, SNIFF_INTERFACE
from src.conf import CLEAR_LOG

checker = Checker()


def packet_handler(packet):
    checker.check(packet)
    Logger.debug(f"Captured Packet: {packet.summary()}\n")


def main():
    if CLEAR_LOG:
        with open(Logger.get_log_file_name(), "w") as log_file:
            log_file.truncate(0)
    Logger.info(
        f"Starting packet capture... Logs will be saved to: {Logger.get_log_file_name()}"
    )
    sniff(prn=packet_handler, store=False, iface=SNIFF_INTERFACE, filter=SNIFF_FILTER)
    Logger.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
