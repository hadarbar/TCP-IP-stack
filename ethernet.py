from typing import List, Tuple
from struct import unpack_from, calcsize
from scapy.all import conf

BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
ETH_PACKET_FORMAT_STRING = "6s6s2s"
MAC_ADDR_LEN = 6


def is_our_packet(raw_packet: bytes,
                 unicast_address: bytes,
                 multicast_addresses: List[bytes] = None) -> bool:
    """
    check if packet dst mac matches our mac address
    """
    our_addresses = [BROADCAST_MAC, unicast_address]
    if multicast_addresses:
        our_addresses += multicast_addresses
    return raw_packet and parse_eth_packet(raw_packet)[0] in our_addresses


def parse_eth_packet(raw_packet: bytes)-> Tuple[bytes, ...]:
    """
    parses ethernet packets and returns the type and raw data
    :param raw_packet: raw packet bytes
    :return: tuple with dst mac, src mac, ether type and the packets data
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


def main():
    iface = "Intel(R) Wi-Fi 6 AX201 160MHz"
    sock = conf.L2socket(iface=iface, promisc=True)
    my_mac = b"\x3c\x58\xc2\xa8\x06\xc4"
    recv = sock.recv_raw()
    sock.send(make_eth_packet(BROADCAST_MAC, my_mac, b"\x08\x06", b"hello"))
    while True:
        if is_our_packet(recv[1], my_mac):
            dst_mac, src_mac, ether_type, data = parse_eth_packet(recv[1])
            print(f"dst mac: {dst_mac.hex(':')}")
            print(f"src mac: {src_mac.hex(':')}")
            print(f"{ether_type=}")
            print(f"{data=}")


if __name__ == "__main__":
    main()
