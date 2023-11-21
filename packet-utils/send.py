#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if(ifacename):
    ifs=get_if_list()
    iface=None # "h1-eno1"
    for i in get_if_list():
        if ifacename in i:
            iface=i
            break
    if not iface:
        print("Cannot find %s interface" % ifacename)
        exit(1)
    return iface

def main():

    if len(sys.argv)<4:
        print('pass 3 arguments: <iface> <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[2])
    iface = get_if(sys.argv[1])

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[3]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()