# eXtensible Network Telemetry

# scapy.contrib.description = VXLAN
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below

#PLT data header
class INT_PLT_HDR(Packet):
    name = "INT_PLT_data_header"
    fields_desc = [ IntField("path_latency_encoding", 0x00000000) ]


class VXLAN_GPE_INT(Packet):
    name = "VXLAN_GPE_INT_header"
    fields_desc = [ XByteField("int_type", 0x01),
                    XByteField("rsvd", 0x00),
                    XByteField("length", 0x00),
                    XByteField("next_proto", 0x03) ]

#PLT data header for GENEVE
class INT_PLT_HDR_GENEVE(Packet):
    name = "INT_PLT_data_header_geneve"
    fields_desc = [ IntField("path_latency_encoding", 0x00000000) ]

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
    fields_desc = [ BitField("bos", 0, 1),
                    XBitField("val", 0x7FFFFFFF, 31) ]


class INT_L45_HEAD(Packet):
    name = "INT_L45_HEAD"
    fields_desc = [ XByteField("int_type", 0x01),
                   XByteField("rsvd0", 0x00),
                   XByteField("length", 0x00),
                   XByteField("rsvd1", 0x00) ]

class INT_L45_TAIL(Packet):
    name = "INT_L45_TAIL"
    fields_desc = [ XByteField("next_proto", 0x01),
                   XShortField("proto_param", 0x0000),
                   XByteField("rsvd", 0x00) ]

class ICMP_INTL45(ICMP):
    name = "ICMP_INTL45"

#  bring back the original packet.py guess_payload_class that is overridden by ICMP
    def guess_payload_class(self, payload):
        """DEV: Guesses the next payload class from layer bonds. Can be overloaded to use a different mechanism."""
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                ok = 1
                for k in fval.keys():
                    if not hasattr(self, k) or fval[k] != self.getfieldval(k):
                        ok = 0
                        break
                if ok:
                    return cls
        return self.default_payload_class(payload)

class TCP_INTL45(TCP):
    name = "TCP_INTL45"

class UDP_INTL45(UDP):
    name = "UDP_INTL45"
