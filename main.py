from scapy.all import conf, get_if_hwaddr
import ethernet
import arp

def main():
    iface = "Intel(R) Wi-Fi 6 AX201 160MHz"
    sock = conf.L2socket(iface=iface, promisc=True)
    my_mac = get_if_hwaddr(iface)
    while True:
        arp.recv_arp(sock, my_mac)


if __name__ == "__main__":
    main()
