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

bind_layers(GRE, ERSPAN, proto=0x88be)
bind_layers(ERSPAN, Ether)

class ERSPAN_III(Packet):
    name = "ERSPAN_III"
    fields_desc = [ BitField("version", 2, 4),
                    BitField("vlan", 0, 12),
                    BitField("priority", 0, 3),
                    BitField("unknown2", 0, 1),
                    BitField("direction", 0, 1),
                    BitField("truncated", 0, 1),
                    BitField("span_id", 0, 10),
                    XIntField("timestamp", 0x00000000),
                    XIntField("sgt_other", 0x00000000)]

class PlatformSpecific(Packet):
    name = "PlatformSpecific"
    fields_desc = [ BitField("platf_id", 0, 6),
                    BitField("info1", 0 ,26),
                    XIntField("info2", 0x00000000)]

bind_layers(GRE, ERSPAN_III, proto=0x22eb)
bind_layers(ERSPAN_III, Ether, sgt_other=0)
bind_layers(ERSPAN_III, PlatformSpecific, sgt_other=1)
bind_layers(PlatformSpecific, Ether)
