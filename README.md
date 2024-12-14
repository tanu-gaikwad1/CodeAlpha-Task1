# CodeAlpha-Task1
CodeAlpha_Project_Task 1 : Basic Network Sniffer.This project will help you understand how data flows on a network and how network packets are structured.

import socket
import struct
import textwrap

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def main():
    # Create a raw socket to capture all traffic
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    print("Listening for network traffic... Press Ctrl+C to stop.")
    
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'\tDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

if __name__ == "__main__":
    main()
