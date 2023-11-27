#!/usr/bin/env python3
import sys

from scapy.all import (
    UDP,
    get_if_list,
    sniff
)
from PMUPacketBuffer import PMUPacketBuffer
from scapy.layers.inet import _IPOption_HDR
import struct
import math
from utils.jpt.jpt_algo import jpt_algo_mags_phase_angles, calc_missing_packet_count, calculate_complex_voltage, jpt_algo, phase_angle_and_magnitude_from_complex_voltage
from send_pmu_packets import generate_pmu_packet_raw_time
from scapy.all import IP, TCP, UDP, Ether, get_if_hwaddr, get_if_list, sendp
import random


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
def handle_pkt(pkt, packet_buffer, iface):
    if UDP in pkt and pkt[UDP].dport == 4712:
        global counter
        parsed_pmu_packet = pmu_packet_parser(pkt[UDP].payload.load)
        if parsed_pmu_packet['stat'] > 0:
            print('generated packet')
            return
        counter += 1
        print(counter)
        if counter > 1:
            if parsed_pmu_packet['soc'] + parsed_pmu_packet['frac_sec'] / 1000000 > packet_buffer.get_recent_timestamp() + 0.02:
                num_missing = calc_missing_packet_count(parsed_pmu_packet['soc'], parsed_pmu_packet['frac_sec'], packet_buffer.get_recent_timestamp(), packet_buffer.get_recent_fracsec())
                generate_new_packets(num_missing, parsed_pmu_packet['soc'], parsed_pmu_packet['frac_sec'], packet_buffer, iface)
        packet_buffer.add_packet(parsed_pmu_packet)


def parse_phasors(phasor_data, settings={"num_phasors": 1, "pmu_measurement_bytes": 8}):
    phasor = {
        "magnitude": struct.unpack('>f', phasor_data[0:int(settings["pmu_measurement_bytes"]/2)])[0],
        "angle": math.degrees(struct.unpack('>f', phasor_data[int(settings["pmu_measurement_bytes"]/2) : settings["pmu_measurement_bytes"]])[0]),
    }
    return [phasor]

def generate_new_packets(num_packets, curr_soc, curr_fracsec, packet_buffer, iface):
    
    jpt_inputs = list(map(lambda x: calculate_complex_voltage(x['phasors'][0]['magnitude'], x['phasors'][0]['angle']), packet_buffer.get_packets()[0:]))
    last_stored_fracsec = packet_buffer.get_recent_fracsec()
    last_stored_soc = packet_buffer.get_recent_soc()

    for i in range(num_packets):
        new_soc = last_stored_soc
        new_frac = last_stored_fracsec + 16666
        complex_voltage_estimate = jpt_algo(jpt_inputs[0], jpt_inputs[1], jpt_inputs[2])
        generated_mag, generated_pa = phase_angle_and_magnitude_from_complex_voltage(complex_voltage_estimate)
        if (new_frac) / 1000000 >= 1:
            new_frac = (new_frac) % 1000000
            new_soc = new_soc + 1

        #make sure not generating too many
        #print(str((curr_soc * 1000000 + curr_fracsec) - (new_soc * 1000000 + new_frac)))
        if (curr_soc * 1000000 + curr_fracsec) - (new_soc * 1000000 + new_frac) > 16000:
            generated_packet = generate_pmu_packet_raw_time(new_soc, new_frac, generated_mag, generated_pa, True)
            send_pmu_packet(generated_packet, iface)
            packet_buffer.add_packet(pmu_packet_parser(generated_packet))

        last_stored_soc = new_soc
        last_stored_fracsec = new_frac
        jpt_inputs = [complex_voltage_estimate] + jpt_inputs[0:2]

def send_pmu_packet(pmu_packet, iface):
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst='10.0.0.5') / UDP(dport=4712, sport=random.randint(49152,65535)) / pmu_packet
    sendp(pkt, iface=iface, verbose=False)

def main():
    packet_buffer = PMUPacketBuffer()
    if len(sys.argv)<2:
        print('pass 1 argument: <iface>')
    iface = get_if(sys.argv[1])
    print("sniffing on %s" % iface)
    sniff(iface = iface,
          prn = lambda p: handle_pkt(p, packet_buffer, iface))

if __name__ == '__main__':
    main()