THIS REPOSITORY IS DEPRECATED AND IS NO LONGER MAINTAINED. P4LANG SOFTWARE NOW
USES UPSTREAM SCAPY, WHICH SUPPORTS VXLAN, GENEVE, ETC.

Barefoot modified scapy, which supports VXLAN. Waiting for VXLAN support to be
added to the main scapy repo.
This modified repo now also supports a ERSPAN-like header.

To install:
sudo python setup.py install

To check that the modifications work, open a scapy CLI (just type 'scapy' in a
terminal) and type the following:

Welcome to Scapy (2.2.0-dev)
>>> load_contrib('vxlan')
>>> Ether()/IP()/UDP()/VXLAN()/Ether()/IP()/TCP()
<Ether  type=0x800 |<IP  frag=0 proto=udp |<UDP  dport=4789 |<VXLAN  |<Ether
type=0x800 |<IP  frag=0 proto=tcp |<TCP  |>>>>>>>
>>> load_contrib('erspan')
>>> Ether()/IP()/GRE()/ERSPAN()/Ether()/IP()/TCP()
<Ether  type=0x800 |<IP  frag=0 proto=gre |<GRE  proto=0x22eb |<ERSPAN  |<Ether
type=0x800 |<IP  frag=0 proto=tcp |<TCP  |>>>>>>>
>>>

Note how the UDP dport and the GRE proto number are updated automatically.

