#  Geneve Draft(GENEVE)
# http://tools.ietf.org/html/draft-gross-geneve-01

# scapy.contrib.description = GENEVE
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below

class GENEVE(Packet):
    name = "GENEVE"
    fields_desc = [ BitField("version",0,2),
                    BitField("optionlen",0,6), 
                    BitField("oam",0,1), 
                    BitField("critical",0,1), 
                    BitField("reserved",0,6), 
                    XShortField("proto", 0x6558),
                    ThreeBytesField("vni", 0),
                    XByteField("reserved2", 0x00)]

    def mysummary(self):
        return self.sprintf("GENEVE (vni=%GENEVE.vni%)")

    def guess_payload_class(self, payload):
        if int(self.optionlen) > 0:
            if ord(payload[0]) == 0 and ord(payload[1]) == 0xAB:
                int_type = ord(payload[2])
                if int_type == 1 or int_type == 2:
                    return GENEVE_INT
                elif int_type == 3:
                    return GENEVE_INT_PLT
            else:
                return Packet.guess_payload_class(self, payload)
        else:
            return Packet.guess_payload_class(self, payload)

bind_layers(UDP, GENEVE, dport=6081)
bind_layers(GENEVE, Ether, proto=0x6558)
