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

bind_layers(VXLAN_GPE, VXLAN_GPE_INT, next_proto=5)

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 0, 2), BitField("rep", 0, 2),
                    BitField("c", 0, 1), BitField("e", 0, 1),
                    BitField("rsvd1", 0, 5), BitField("ins_cnt", 1, 5),
                    BitField("max_hop_cnt", 32, 8),
                    BitField("total_hop_cnt", 0, 8),
                    ShortField("inst_mask", 0x8000),
                    ShortField("rsvd2", 0x0000)]

bind_layers(VXLAN_GPE_INT, INT_META_HDR)
bind_layers(ERSPAN_III, INT_META_HDR)  # this for the INT report from sink
# Add binding to GENEVE

# INT data header
class INT_hop_info(Packet):
    name = "INT_hop_info"
    fields_desc = [ BitField("bos", 0, 1),
                    XBitField("val", 0x7FFFFFFF, 31) ]

bind_layers(INT_META_HDR, INT_hop_info)

class VXLAN_GPE_INT_PLT(Packet):
    name = "VXLAN_GPE_INT_PLT_header"
    fields_desc = [ XByteField("int_type", 0x03),
                    XByteField("rsvd", 0x00),
                    XByteField("length", 0x03),
                    XByteField("next_proto", 0x05) ]

bind_layers(VXLAN_GPE, VXLAN_GPE_INT_PLT, next_proto=5)

#PLT data header
class INT_PLT_HDR(Packet):
    name = "INT_PLT_data_header"
    fields_desc = [ IntField("path_encoding", 0x00000000),
                    IntField("latency_encoding", 0x00000000) ]

bind_layers(VXLAN_GPE_INT_PLT, INT_PLT_HDR)
bind_layers(VXLAN_GPE_INT_PLT, VXLAN_GPE_INT, next_proto=5)