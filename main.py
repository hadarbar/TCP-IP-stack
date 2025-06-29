from scapy.all import conf, get_if_hwaddr
import ethernet

def main():
    iface = "Intel(R) Wi-Fi 6 AX201 160MHz"
    sock = conf.L2socket(iface=iface, promisc=True)
    my_mac = get_if_hwaddr(iface)
    while True:
        recv = sock.recv_raw()
        if ethernet.is_our_packet(recv[1], bytes.fromhex(my_mac.replace(":", ""))):
            dst_mac, src_mac, ether_type, data = ethernet.parse_eth_packet(recv[1])
            print(f"dst mac: {dst_mac.hex(':')}")
            print(f"src mac: {src_mac.hex(':')}")
            print(f"{ether_type=}")
            print(f"{data=}")


if __name__ == "__main__":
    main()
