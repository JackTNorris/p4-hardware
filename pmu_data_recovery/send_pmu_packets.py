#!/usr/bin/env python3
import random
import socket
import sys
import socket
from datetime import datetime
import math
import struct
import pandas as pd
import sys
from utils.pmu_csv_parser import parse_csv_data

from scapy.all import IP, TCP, UDP, Ether, get_if_hwaddr, get_if_list, sendp


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


def generate_pmu_packet(time, voltage, angle, settings={"pmu_measurement_bytes": 8, "destination_ip": "192.168.0.100", "destination_port": 4712}):
    # Define the PMU packet as a byte string
    datetime_str = str(time)[:26]
    global index
    try:
        dt = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        dt = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')

    # 2 byte

    sync = b'\xAA\x01'
    #sync = index.to_bytes(2, 'big')


    # 2 byte, 44 for 32 bit values of PMU, 40 for 16 bit values of PMU
    # 36 - 8 + 8 * number of PMUs || 36 - 8 + 4 * number PMUs
    frame_size = b'\x00\x24'

    # 2 byte, 12 for this
    id_code = b'\x00\x0C'

    # 4 byte
    soc = int(dt.strftime("%s")).to_bytes(4, 'big')
    #print(dt.strftime("%s"))
    # 4 byte
    frac_sec = dt.microsecond.to_bytes(4, 'big')
    # 2 byte (no errors)
    stat = b'\x00\x00'

    # 4 or 8 byte x number of phasors (see doc, 8 is for float)
    voltage_bytes = struct.pack('>f', voltage)
    angle_bytes = struct.pack('>f', math.radians(angle))
    phasors = voltage_bytes + angle_bytes

    # 2 byte, assumed 60
    freq = b'\x09\xC4'

    # 2 byte
    dfreq = b'\x00\x00'

    # 4 byte
    analog = b'\x00\x00\x00\x00'

    # 2 byte
    digital = b'\x00\x00'

    # 2 byte
    chk = b'\x00\x00'

    pmu_packet_payload = sync + frame_size + id_code + soc + frac_sec + stat + phasors + freq + dfreq + analog + digital + chk

    return pmu_packet_payload


def main():
    if len(sys.argv)<3:
        print('pass 2 arguments: <iface> <destination>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[2])
    iface = get_if(sys.argv[1])

    print("sending on interface %s to %s" % (iface, str(addr)))
    pmu_csv_data = parse_csv_data(
        './data/pmu12.csv',
        "TimeTag",
        ["Magnitude01", "Magnitude02", "Magnitude03"],
        ["Angle01", "Angle02", "Angle03"]
    )

    num_to_send = len(pmu_csv_data["times"])
    num_to_send - 50
    for i in range(num_to_send):
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt /IP(dst=addr) / UDP(dport=1234, sport=random.randint(49152,65535)) / generate_pmu_packet(pmu_csv_data["times"][i], pmu_csv_data["magnitudes"][0][i], pmu_csv_data["phase_angles"][0][i])
        sendp(pkt, iface=iface, verbose=False)
        print(i)


if __name__ == '__main__':
    main()