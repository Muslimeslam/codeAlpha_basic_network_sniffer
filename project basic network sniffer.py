from scapy.all import *

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if the packet has a TCP layer
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")

        # Check if the packet has a UDP layer
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
    else:
        print("Non-IP Packet detected!")

# Start sniffing the network
sniff(prn=packet_callback, store=0)
