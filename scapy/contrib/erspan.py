# Encapsulated Remote Switch Packet Analysis

# scapy.contrib.description = VXLAN
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import *

class ERSPAN(Packet):
    name = "ERSPAN"
    fields_desc = [ BitField("version", 1, 4),
                    BitField("vlan", 0, 12),
                    BitField("priority", 0, 3),
                    BitField("unknown2", 0, 1),
                    BitField("direction", 0, 1),
                    BitField("truncated", 0, 1),
                    BitField("span_id", 0, 10),
                    XIntField("unknown7", 0x00000000)]

bind_layers(GRE, ERSPAN, proto=0x22eb)
bind_layers(ERSPAN, Ether)
