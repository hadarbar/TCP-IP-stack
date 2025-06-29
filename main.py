from scapy.all import conf, get_if_hwaddr

import arp
import ethernet

def print_arps(sock: conf.L2socket, my_mac: str):
    """
    loop that listens on socket and prints the arp packets
    """
    while True:
        _, frame, _ = sock.recv_raw()
        if not ethernet.is_our_packet(frame, bytes.fromhex(my_mac.replace(":", ""))):
            continue
        dst_mac, src_mac, ether_type, data = ethernet.parse_eth_packet(frame)
        if ether_type == arp.ARP_ETHER_TYPE:
            arp.print_arp(data)


def main():
    iface = "Intel(R) Wi-Fi 6 AX201 160MHz"
    sock = conf.L2socket(iface=iface, promisc=True)
    my_mac = get_if_hwaddr(iface)
    arp.send_arp_request(sock, "10.0.0.138", "10.0.0.9", my_mac)
    print_arps(sock, my_mac)


if __name__ == "__main__":
    main()
