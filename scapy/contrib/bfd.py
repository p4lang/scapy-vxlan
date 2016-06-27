# BFD - Bidirectional Forwarding Detection - RFC 5880, 5881

# scapy.contrib.description = BFD
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below

class BFD(Packet):
    name = "BFD"
    fields_desc = [ 
                    BitField("version" , 1 , 3),
                    BitField("diag" , 0 , 5),
                    BitField("sta" , 3 , 2),
                    FlagsField("flags", 0x00, 6, ['P', 'F', 'C', 'A', 'D', 'M']),
                    XByteField("detect_mult", 0x03),
                    XByteField("len", 24),
                    BitField("my_discriminator" , 0x11111111 , 32),
                    BitField("your_discriminator" , 0x22222222 , 32),
                    BitField("min_tx_interval" , 1000000000, 32),
                    BitField("min_rx_interval" , 1000000000, 32),
                    BitField("echo_rx_interval" , 1000000000, 32) ]

    def mysummary(self):
        return self.sprintf("BFD (my_disc=%BFD.my_discriminator%, your_disc=%BFD.my_discriminator%)")

bind_layers(UDP, BFD, dport=3784)
