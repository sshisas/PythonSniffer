'''
Sarah Shinn
Assignment 12
3/14/2023
'''

import os

from prettytable import PrettyTable

# Get the HOST to Sniff From
hostname = socket.gethostname()
HOST = socket.gethostbyname(hostname)

# HOST = 'localhost'

import ipaddress
import struct


class IP:
    def __init__(self, buff=None):

        header = struct.unpack("<BBHHHBBH4s4s", buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}


def main():

    socket_protocol = socket.IPPROTO_IP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    capture_dict = {}

    for i in range(1, 31):

        packet = sniffer.recvfrom(65565)  # Wait for Packet
        base_packet = packet[0]  # Extract Packet Data from tuple
        pck_header = base_packet[0:20]  # Extract the packet header

        ip_obj = IP(pck_header)  # Create the IP Object

        # Lookup the protocol name
        try:
            protocol_name = ip_obj.protocol_map[ip_obj.protocol_num]
        except:
            protocol_name = "Unknown"

        src_ip = str(ip_obj.src_address)
        dst_ip = str(ip_obj.dst_address)

        key = (src_ip, dst_ip, protocol_name)
        if key not in capture_dict:
            capture_dict[key] = 0
        capture_dict[key] += 1

        print("SRC-IP  :", src_ip)
        print("DST-IP  :", dst_ip)
        print("Protocol:", protocol_name)

        if len(capture_dict) >= 10000:
            break

    tbl = PrettyTable(["Occurs", "SRC", "DST", "Protocol"])
    for key, value in sorted(capture_dict.items(), key=lambda x: x[1], reverse=True):
        tbl.add_row([value, key[0], key[1], key[2]])
    print(tbl)

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == "__main__":
    main()