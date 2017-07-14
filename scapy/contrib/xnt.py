# eXtensible Network Telemetry

# scapy.contrib.description = VXLAN
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below


class VXLAN_GPE_INT(Packet):
    name = "VXLAN_GPE_INT_header"
    fields_desc = [ XByteField("int_type", 0x01),
                    XByteField("rsvd", 0x00),
                    XByteField("length", 0x00),
                    XByteField("next_proto", 0x03) ]

class GENEVE_INT(Packet):
    name = "GENEVE_INT_header"
    fields_desc = [ XShortField("int_opt", 0x0103),
                    XByteField("int_type", 0x01),
                    BitField("rsvd", 0 , 3),
                    BitField("length", 2, 5)]

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 0, 2), BitField("rep", 0, 2),
                    BitField("c", 0, 1), BitField("e", 0, 1),
                    BitField("rsvd1", 0, 5), BitField("ins_cnt", 1, 5),
                    BitField("max_hop_cnt", 32, 8),
                    BitField("total_hop_cnt", 0, 8),
                    ShortField("inst_mask", 0x8000),
                    ShortField("rsvd2", 0x0000)]

# INT data header
class INT_hop_info(Packet):
    name = "INT_hop_info"
    fields_desc = [ XBitField("val", 0xFFFFFFFF, 32) ]
