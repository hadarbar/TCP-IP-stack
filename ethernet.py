from typing import Union,Tuple
from struct import unpack_from, calcsize

BROADCAST = b"\xff\xff\xff\xff\xff\xff"
PACKET_FORMAT_STRING = "6s6s2s"
CRC_LEN = 4

def parse_eth_packet(raw_packet: bytes,
                 unicast_address: bytes,
                 multicast_address: Union[bytes, None] = None)-> Union[Tuple[bytes, ...], None]:
    """
    parses ethernet packets and returns the type and raw data of the dst mac corresponds to listening iface
    :param raw_packet: raw packet bytes
    :param unicast_address: the ifaces unicast address
    :param multicast_address: the ifaces multicast address
    :return: tuple with dst mac, src mac, type and packet data, if dst mac is ifaces, else return none
    """
    headers_size = calcsize(PACKET_FORMAT_STRING)
    dst_mac, src_mac, ether_type = unpack_from(PACKET_FORMAT_STRING, raw_packet)
    valid_addresses = [BROADCAST, unicast_address, multicast_address]
    if dst_mac in valid_addresses:
        return dst_mac, src_mac, ether_type, raw_packet[headers_size:-CRC_LEN]

    return None
