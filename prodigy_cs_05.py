from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Raw

def packet_analysis(packet):
    # Check if the packet is IPv4
    if packet.haslayer(IP):
        # Get source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Get the protocol number
        protocol = packet[IP].proto

        # Initialize payload
        payload = b""

        # Check if the packet has a Raw layer (which contains the payload)
        if packet.haslayer(Raw):
            payload = packet[Raw].load

        # Print packet information
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 32)

# Start sniffing for IPv4 packets
sniff(filter="ip", prn=packet_analysis)