import scapy.all as scapy

def packet_handler(packet):
    print(packet)

def main():
    scapy.sniff(prn=packet_handler)

if __name__ == "__main__":
    main()
