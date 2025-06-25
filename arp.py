import ethernet
from struct import pack, unpack_from
from typing import Tuple

ARP_START = b"\x00\x01\x08\x00\x06\x04"
OPERATION_REQUEST = 1
OPERATION_REPLY = 2

ARP_PACKET_FORMAT_STRING = ">6sh6s4s6s4s"

def make_arp_request(dst_ip: str, src_ip: str, src_mac: str) -> bytes:
    """
    make arp request packet
    :return: bytes of arp request packet
    """
    dst_ip_bytes = ip_str_to_bytes(dst_ip)
    src_ip_bytes = ip_str_to_bytes(src_ip)
    arp_data = pack(ARP_PACKET_FORMAT_STRING,
                         ARP_START,
                         OPERATION_REQUEST,
                         bytes.fromhex(src_mac.replace(":", "")),
                         src_ip_bytes,
                         ethernet.BROADCAST_MAC,
                         dst_ip_bytes)
    packet = ethernet.make_eth_packet(ethernet.BROADCAST_MAC,
                                      bytes.fromhex(src_mac.replace(":", "")),
                                      ethernet.ETHER_TYPES["ARP"],
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
                    ARP_START,
                    OPERATION_REPLY,
                    bytes.fromhex(src_mac.replace(":", "")),
                    src_ip_bytes,
                    bytes.fromhex(dst_mac.replace(":", "")),
                    dst_ip_bytes)
    packet = ethernet.make_eth_packet(bytes.fromhex(dst_mac.replace(":", "")),
                                      bytes.fromhex(src_mac.replace(":", "")),
                                      ethernet.ETHER_TYPES["ARP"], arp_data)
    return packet

def parse_arp_packet(raw_data: bytes) -> Tuple[int, str, str, str, str]:
    """
    parse arp packet
    :param raw_data: data of layer two
    :return:
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
    if operation == OPERATION_REQUEST:
        print("ARP request:")
        print(f"Who has {dst_ip}? Tell {src_ip}")
    else:
        print("ARP reply:")
        print(f"{src_ip} is at {src_mac}")