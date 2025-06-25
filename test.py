from scapy.all import conf
import arp
import ethernet

IFACE = "Intel(R) Wi-Fi 6 AX201 160MHz"

def main():
    sock = conf.L2socket(iface=IFACE, promisc=True)
    my_mac = "3C:58:C2:A8:06:C4"

    arp_request = arp.make_arp_request("10.0.0.1", "111.111.111.111", my_mac)
    sock.send(arp_request)

    while True:
        recv = sock.recv_raw()
        if ethernet.is_our_packet(recv[1], bytes.fromhex(my_mac.replace(":", ""))):
            dst_mac, src_mac, ether_type, data = ethernet.parse_eth_packet(recv[1])
            if ether_type == ethernet.ETHER_TYPES[""]:
                arp.print_arp(data)


if __name__ == "__main__":
    main()
