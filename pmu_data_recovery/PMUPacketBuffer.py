class PMUPacketBuffer:
    def __init__(self):
        self.buffer = []

    def add_packet(self, packet):
        # Assuming packet is a dict with 'soc' and 'fracsec' keys
        self.buffer.append(packet)
        # Sort the buffer by 'soc' and 'fracsec' in descending order (most recent first)
        self.buffer.sort(key=lambda x: (x['soc'], x['frac_sec']), reverse=True)
        # Keep only the 3 most recent packets
        self.buffer = self.buffer[:3]
    
    def get_recent_timestamp(self):
        return self.buffer[0]['soc'] + self.buffer[0]['frac_sec'] / 1000000

    def get_packets(self):
        return self.buffer