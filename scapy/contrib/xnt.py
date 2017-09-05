# eXtensible Network Telemetry

# scapy.contrib.description = VXLAN
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below

def instantiate_payload(cls, s, _underlayer, one_layer=True):
    try:
        p = cls(s, _internal=1, _underlayer=_underlayer)
    except KeyboardInterrupt:
        raise
    except:
        p = conf.raw_layer(s, _internal=1, _underlayer=_underlayer)
    _underlayer.add_payload(p)
    if one_layer:
        if p.payload==None or isinstance(p.payload, NoPayload):
            s=None
        else:
            s=str(p.payload)
            p.remove_payload()
    return (s, p)

def find_INT_hop_info(s, pkt):
    instantiate_payload(pkt.guess_payload_class(s), s, pkt, False)

    # find first instande of INT_hop_info
    used_bytes = len(pkt.self_build()) # just my length
    p = pkt.payload;
    used_bytes += len(p.self_build())
    while (p.payload and p.payload!=None and
           p.payload!=NoPayload and not
           isinstance(p.payload, INT_hop_info)):
        p = p.payload
        used_bytes += len(p.self_build())

    if not p or p.payload==None or p.payload==NoPayload:
        return

    # remove INT hop infos from int_meta_header
    s=str(p.payload)
    p.remove_payload()
    return (s, p, used_bytes)


class VXLAN_GPE_INT(Packet):
    name = "VXLAN_GPE_INT_header"
    fields_desc = [ XByteField("int_type", 0x01),
                    XByteField("rsvd", 0x00),
                    XByteField("length", 0x00),
                    XByteField("next_proto", 0x03) ]
    def do_dissect_payload(self, s):
        (s, last_header, used_bytes) = find_INT_hop_info(s, self)

        # extract hop info
        while s and used_bytes < self.length * 4:
            s, last_header = instantiate_payload(INT_hop_info, s, last_header)
            used_bytes+=len(last_header)

        # extract ethernet after INT
        if s:
            instantiate_payload(Ether, s, last_header, False)

class GENEVE_INT(Packet):
    name = "GENEVE_INT_header"
    fields_desc = [ XShortField("int_opt", 0x0103),
                    XByteField("int_type", 0x01),
                    BitField("rsvd", 0 , 3),
                    BitField("length", 2, 5)]
    def do_dissect_payload(self, s):
        (s, last_header, used_bytes) = find_INT_hop_info(s, self)

        # extract hop info
        while s and used_bytes < self.length * 4:
            s, last_header = instantiate_payload(INT_hop_info, s, last_header)
            used_bytes+=len(last_header)

        # extract ethernet after INT
        if s:
            instantiate_payload(Ether, s, last_header, False)

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 0, 2), BitField("rep", 0, 2),
                    BitField("c", 0, 1), BitField("e", 0, 1),
                    BitField("d", 0, 1),
                    BitField("rsvd1", 0, 4), BitField("ins_cnt", 1, 5),
                    BitField("max_hop_cnt", 32, 8),
                    BitField("total_hop_cnt", 0, 8),
                    ShortField("inst_mask", 0x8000),
                    XShortField("rsvd2_digest", 0x0000)]
    def do_dissect_payload(self, s):
        stack_max_length=bin(self.inst_mask).count("1") * self.total_hop_cnt
        # extract hop info
        stack_length = 0
        last_header = self
        while s and  stack_length < stack_max_length:
            s, last_header = instantiate_payload(INT_hop_info, s, last_header)
            stack_length+=1

        p = conf.raw_layer(s, _internal=1, _underlayer=last_header)
        last_header.add_payload(p)

# INT data header
class INT_hop_info(Packet):
    name = "INT_hop_info"
    fields_desc = [ XBitField("val", 0xFFFFFFFF, 32) ]
