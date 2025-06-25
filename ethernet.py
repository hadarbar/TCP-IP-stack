from typing import Optional, Tuple
from struct import unpack_from, calcsize

BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
ETH_PACKET_FORMAT_STRING = "6s6s2s"
ETHER_TYPES = {"ARP" : b"\x08\x06"}
MAC_ADDR_LEN = 6

def is_our_packet(raw_packet: bytes,
                 unicast_address: bytes,
                 multicast_address: Optional[bytes] = None) -> bool:
    """
    check if packet dst mac matches our mac address
    """
    our_addresses = [BROADCAST_MAC, unicast_address, multicast_address]
    if raw_packet and raw_packet[:MAC_ADDR_LEN] in our_addresses:
        return True
    else:
        return False

def parse_eth_frame(raw_packet: bytes)-> Tuple[bytes, ...]:
    """
    parses ethernet packets and returns the type and raw data
    :param raw_packet: raw packet bytes
    :return: tuple
    """
    headers_size = calcsize(ETH_PACKET_FORMAT_STRING)
    dst_mac, src_mac, ether_type = unpack_from(ETH_PACKET_FORMAT_STRING, raw_packet)
    return dst_mac, src_mac, ether_type, raw_packet[headers_size:]

def make_eth_packet(dst_mac: bytes, src_mac: bytes, ether_type: bytes, data: bytes) -> bytes:
    """
    build ether packet and return bytes of full packet
    """

    packet = dst_mac + src_mac + ether_type + data
    return packet
