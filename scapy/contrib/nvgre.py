# Network Virtualization using Generic Rotuing Encapsulation (NVGRE)
#https://tools.ietf.org/html/draft-sridharan-virtualization-nvgre-00

# scapy.contrib.description = NVGRE
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below

class NVGRE(Packet):
    name = "NVGRE"

    fields_desc = [ BitField("chksum_present",0,1),
                    BitField("routing_present",0,1),
                    BitField("key_present",1,1),
                    BitField("seqnum_present",0,1),
                    BitField("reserved",0,9),
                    BitField("version",0,3),
                    XShortField("proto", 0x6558),
                    ThreeBytesField("vsid", 0),
                    XByteField("flowid", 0)
                    ]

    def mysummary(self):
        return self.sprintf("NVGRE (vni=%NVGRE.vsid%)")

bind_layers(IP, NVGRE, proto=47)
bind_layers(NVGRE, Ether)
