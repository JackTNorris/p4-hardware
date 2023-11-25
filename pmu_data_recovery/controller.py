#!/usr/bin/env python3
import sys

from scapy.all import (
    TCP,
    UDP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from PMUPacketBuffer import PMUPacketBuffer
from scapy.layers.inet import _IPOption_HDR
import struct
import math


def get_if(ifacename):
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if ifacename in i:
            iface=i
            break;
    if not iface:
        print("Cannot find %s interface" % ifacename)
        exit(1)
    return iface

def pmu_packet_parser(data, settings={"pmu_measurement_bytes": 8, "num_phasors": 1, "freq_bytes": 2, "dfreq_bytes": 2}):
    freq_start_byte = 16 + settings["num_phasors"] * settings["pmu_measurement_bytes"]
    dfreq_start_byte = freq_start_byte + settings["freq_bytes"]
    analog_start_byte = dfreq_start_byte + settings["dfreq_bytes"]
    digital_start_byte = analog_start_byte + 4
    chk_start_byte = digital_start_byte + 2

    # convert each field to correct data type
    pmu_packet = {
        "sync": int.from_bytes(data[0:2], byteorder="big"),
        "frame_size": int.from_bytes(data[2:4], byteorder="big"),
        "id_code": int.from_bytes(data[4:6], byteorder="big"),
        "soc": int.from_bytes(data[6:10], byteorder="big"),
        "frac_sec": int.from_bytes(data[10:14], byteorder="big"),
        "stat": int.from_bytes(data[14:16], byteorder="big"),
        "phasors": parse_phasors(data[16:16 + settings["pmu_measurement_bytes"]], {"num_phasors": settings["num_phasors"], "pmu_measurement_bytes": settings["pmu_measurement_bytes"]}),
        "freq": data[freq_start_byte:dfreq_start_byte],
        "dfreq": data[dfreq_start_byte:analog_start_byte],
        "analog": data[analog_start_byte:digital_start_byte],
        "digital": data[digital_start_byte:chk_start_byte],
        "chk": data[chk_start_byte:]
    }

    return pmu_packet

counter = 0
def handle_pkt(pkt, packet_buffer):
    if UDP in pkt and pkt[UDP].dport == 1234:
        global counter
        counter += 1
        parsed_pmu_packet = pmu_packet_parser(pkt[UDP].payload.load)
        if counter > 1:
            if parsed_pmu_packet['soc'] + parsed_pmu_packet['frac_sec'] / 1000000 > packet_buffer.get_recent_timestamp() + 0.02:
                print("A packet has been lost @ row", counter + 1)
        packet_buffer.add_packet(parsed_pmu_packet)


def parse_phasors(phasor_data, settings={"num_phasors": 1, "pmu_measurement_bytes": 8}):
    phasor = {
        "magnitude": struct.unpack('>f', phasor_data[0:int(settings["pmu_measurement_bytes"]/2)])[0],
        "angle": math.degrees(struct.unpack('>f', phasor_data[int(settings["pmu_measurement_bytes"]/2) : settings["pmu_measurement_bytes"]])[0]),
    }
    return [phasor]

def main():
    packet_buffer = PMUPacketBuffer()
    if len(sys.argv)<2:
        print('pass 1 argument: <iface>')
    iface = get_if(sys.argv[1])
    print("sniffing on %s" % iface)
    sniff(iface = iface,
          prn = lambda p: handle_pkt(p, packet_buffer))

if __name__ == '__main__':
    main()