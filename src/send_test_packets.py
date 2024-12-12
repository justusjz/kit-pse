# send test packets
# set iface on sniff function to loopback interface, for macOS on "lo0"
from scapy.all import send
from scapy.layers.inet import TCP, IP, ICMP

target_ip = "127.0.0.1"
target_port = 80

# NULL-Scan Packet with no flags
null_pkt = IP(dst=target_ip)/TCP(dport=target_port, flags=0)
send(null_pkt, count=5)

# Send ICMP flood
icmp_packet = IP(dst=target_ip) / ICMP()
send(icmp_packet, count=200, inter=0.001)

# Syn-Fin Packet
syn_fin_packet = IP(dst=target_ip)/TCP(dport=target_port, flags="FS")
send(syn_fin_packet, count=5)

# XMAS-Scan packet Flags="FPU"
xmas_packet = IP(dst=target_ip)/TCP(dport=target_port, flags="FPU")
send(xmas_packet, count=5)