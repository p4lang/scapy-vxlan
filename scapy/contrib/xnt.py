# eXtensible Network Telemetry

# scapy.contrib.description = VXLAN
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below

class VXLAN_GPE_INT(Packet):
    name = "VXLAN_GPE_INT_header"
    fields_desc = [ FlagsField("flags", 0x08, 8, ['R', 'R', 'R', 'R', 'P', 'R', 'R', 'R']),
                    XShortField("length", 0x0000),
                    XByteField("next_proto", 0x03) ]

bind_layers(VXLAN_GPE, VXLAN_GPE_INT, next_proto=5)

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 0, 2),
                    BitField("dir", 0, 1), BitField("rep", 0, 2),
                    BitField("o", 0, 1),
                    BitField("rsvd1", 0, 4), BitField("ins_cnt", 1, 5),
                    BitField("max_cnt", 32, 8), BitField("e", 0, 1),
                    BitField("total_cnt", 0, 8),
                    BitField("inst_mask", 128, 8),
                    #FlagsField("inst_mask", 0x80, 8, ['switch_id', 'igr_port',
                    #            'tstamp', 'egr_port', 'hop_latency',
                    #            'q_occupancy', 'q_congestion', 
                    #            'tx_utilization']),
                    BitField("unused_instr_mask", 0, 8),
                    ShortField("rsvd2", 0x0000)]

bind_layers(VXLAN_GPE_INT, INT_META_HDR)
# Add binding to GENEVE

## Find way to add variable number of int_field headers, one for each bit in
## inst_mask 
