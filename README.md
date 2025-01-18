import socket
import struct
import textwrap

# Function to format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Function to unpack Ethernet frame
def unpack_ethernet_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(protocol), data[14:]

# Function to format MAC addresses
def get_mac_address(mac_bytes):
    return ':'.join(map('{:02x}'.format, mac_bytes)).upper()

# Function to unpack IPv4 packets
def unpack_ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src = '.'.join(map(str, src))
    target = '.'.join(map(str, target))
    return ttl, proto, src, target, data[header_length:]

# Main function to start packet sniffing
def sniff_packets():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Packet Sniffer started. Listening for packets...\n")
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
            print("\nEthernet Frame:")
            print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

            # Handle IPv4 packets
            if eth_proto == 8:
                ttl, proto, src, target, data = unpack_ipv4_packet(data)
                print("IPv4 Packet:")
                print(f"Source IP: {src}, Destination IP: {target}, TTL: {ttl}")

                # Display payload
                print("Data:")
                print(format_multi_line("\t", data))
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped.")

# Run the program
if __name__ == "__main__":
    sniff_packets()
# Network-Packet-Sniffer-and-Analyzer
This project involves creating a network packet sniffer that captures and analyzes packets transmitted over a network. It allows users to monitor network traffic, identify suspicious activities, and inspect packet details (e.g., source/destination IPs, ports, protocols).
