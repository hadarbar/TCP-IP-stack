from enum import Enum
from typing import Tuple, Optional
from struct import pack, unpack_from

from scapy.all import conf

import ethernet


ARP_CONST_FIELDS_IPV4 = b"\x00\x01\x08\x00\x06\x04"
ARP_ETHER_TYPE = b"\x08\x06"
ARP_PACKET_FORMAT_STRING = ">6sh6s4s6s4s"

class ArpOperations(Enum):
    REQUEST = 1
    REPLY = 2


def make_arp_request(dst_ip: str, src_ip: str, src_mac: str) -> bytes:
    """
    make arp request packet
    :return: bytes of arp request packet
    """
    dst_ip_bytes = ip_str_to_bytes(dst_ip)
    src_ip_bytes = ip_str_to_bytes(src_ip)
    arp_data = pack(ARP_PACKET_FORMAT_STRING,
                         ARP_CONST_FIELDS_IPV4,
                         ArpOperations.REQUEST.value,
                         bytes.fromhex(src_mac.replace(":", "")),
                         src_ip_bytes,
                         ethernet.BROADCAST_MAC,
                         dst_ip_bytes)
    packet = ethernet.make_eth_packet(ethernet.BROADCAST_MAC,
                                      bytes.fromhex(src_mac.replace(":", "")),
                                      ARP_ETHER_TYPE,
                                      arp_data)
    return packet


def make_arp_reply(dst_ip: str, src_ip: str, dst_mac: str, src_mac: str) -> bytes:
    """
    make arp reply packet
    :return: full arp reply packet
    """
    src_ip_bytes = ip_str_to_bytes(src_ip)
    dst_ip_bytes = ip_str_to_bytes(dst_ip)
    arp_data = pack(ARP_PACKET_FORMAT_STRING,
                    ARP_CONST_FIELDS_IPV4,
                    ArpOperations.REPLY.value,
                    bytes.fromhex(src_mac.replace(":", "")),
                    src_ip_bytes,
                    bytes.fromhex(dst_mac.replace(":", "")),
                    dst_ip_bytes)
    packet = ethernet.make_eth_packet(bytes.fromhex(dst_mac.replace(":", "")),
                                      bytes.fromhex(src_mac.replace(":", "")),
                                      ARP_ETHER_TYPE, arp_data)
    return packet


def parse_arp_packet(raw_data: bytes) -> Tuple[int, str, str, str, str]:
    """
    parse arp packet
    :param raw_data: raw data of arp packet
    :return: fields of arp packet
    """
    headers, operation, src_mac, src_ip, dst_mac, dst_ip = unpack_from(ARP_PACKET_FORMAT_STRING, raw_data)
    src_ip_str = ip_bytes_to_str(src_ip)
    dst_ip_str = ip_bytes_to_str(dst_ip)
    return operation, src_mac.hex(":"), src_ip_str, dst_mac.hex(":"), dst_ip_str


def ip_str_to_bytes(ip: str) -> bytes:
    """
    return bytes of ip from ip string
    """
    ip_values = ip.split(".")
    ip_bytes = [int(b).to_bytes() for b in ip_values]
    return b"".join(ip_bytes)


def ip_bytes_to_str(ip: bytes) -> str:
    """
    convert ip in bytes to ip string
    """
    ip_string = ".".join([str(b) for b in ip])
    return ip_string


def print_arp(raw_data: bytes) -> None:
    """
    print arp packet nicely
    """
    operation, src_mac, src_ip, dst_mac, dst_ip = parse_arp_packet(raw_data)
    if operation == ArpOperations.REQUEST.value:
        print("ARP request:")
    else:
        print("ARP reply:")

    print(f"{src_ip=}")
    print(f"{src_mac=}")
    print(f"{dst_ip=}")
    print(f"{dst_mac=}")

def send_arp_request(socket: conf.L2socket, dst_ip: str, src_ip: str, src_mac: str) -> None:
    """
    make and send arp request through socket
    """
    socket.send(make_arp_request(dst_ip, src_ip, src_mac))

def send_arp_reply(socket: conf.L2socket, dst_ip: str, src_ip: str, dst_mac: str, src_mac: str) -> None:
    """
    make and send arp reply through socket
    """
    socket.send(make_arp_reply(dst_ip, src_ip, dst_mac, src_mac))
