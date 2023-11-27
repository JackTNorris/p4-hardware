import math
import cmath

wt = 0
#feed in the magnitudes from most recent to least recent
def jpt_algo_mags_phase_angles(mags, phase_angles):
    Ks = []
    for mag, phase_angle in zip(mags, phase_angles):
        Ks.append(calculate_complex_voltage(mag, phase_angle))
    #returns a tuple of magnitude and phase angle
    return phase_angle_and_magnitude_from_complex_voltage(jpt_algo(Ks[0], Ks[1], Ks[2]))


#jpt algorithm
def jpt_algo(kMin1, kMin2, kMin3):
    #to find the measurement at time k, take
    # the 3 measurements prior (kMin1 ... KMin3) and plug it into the following to get
    return 3 * kMin1 - 3 * kMin2 + kMin3

# V = magnitude  * e^(j*(wt + phase_angle)) http://hyperphysics.phy-astr.gsu.edu/hbase/electric/impcom.html#c1
# given the magnitude and phase angle component, we convert he voltage into the form a + bi
def calculate_complex_voltage(magnitude, phase_angle):
    #e^ix = cos x + i sin x #euler's formula
    # V = magnitude * cos(wt + phase_angle) + magnitude * i * sin(wt + phase_angle)
    real_portion = math.cos(math.radians(wt + phase_angle)) * magnitude
    imaginary_portion = math.sin(math.radians(wt + phase_angle)) * magnitude
    voltage = complex(real_portion, imaginary_portion)
    return voltage

# based on a voltage in the form V = a + bi, it extracts the magnitude and the voltage
def phase_angle_and_magnitude_from_complex_voltage(voltage):
    phase_angle = cmath.phase(voltage)
    # phase_angle =  math.atan(voltage.imag / voltage.real) - wt #finds phase angle in radians
    magnitude = math.sqrt(voltage.real**2 + voltage.imag**2)
    return magnitude, math.degrees(phase_angle)

def calc_missing_packet_count(curr_soc, curr_fracsec, last_stored_soc, last_stored_fracsec, freq_hz=60):
    soc_diff = curr_soc - last_stored_soc
    fracsec_diff = 0
    if curr_fracsec < last_stored_fracsec:
        soc_diff -= 1
        fracsec_diff = 1000000 - last_stored_fracsec + curr_fracsec
    else:
        fracsec_diff = curr_fracsec - last_stored_fracsec
    if soc_diff < 0:
        soc_diff = 0

    total_fracsec_passed = soc_diff * 1000000 + fracsec_diff
    #17000
    #print(total_fracsec_passed / 1000000 * 60)
    missing_packet_count = round(total_fracsec_passed / 1000000 * 60) - 1

    return missing_packet_count

