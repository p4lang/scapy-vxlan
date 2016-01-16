"""
Packet sending and receiving with nanomsg
"""

import threading
from scapy.config import conf
import struct
import time

while conf.use_nanomsg:

    try:
        import nnpy
    except ImportError:
        conf.use_nanomsg = False
        continue

    class NNSocket:
        MSG_TYPE_PACKET_IN = 3
        MSG_TYPE_PACKET_OUT = 4

        lock = threading.Lock()
        nn_sockets = {}
        nn_sockets_cnt = {}

        def __init__(self, addr):
            self.addr = addr
            self.socket = nnpy.Socket(nnpy.AF_SP, nnpy.PAIR)
            self.socket.connect(addr)

        def fileno(self):
            return self.socket.getsockopt(nnpy.SOL_SOCKET, nnpy.RCVFD)

        def recv(self):
            msg = self.socket.recv()
            fmt = "<iii"
            msg_type, port_number, length = struct.unpack_from(fmt, msg)
            hdr_size = struct.calcsize(fmt)
            msg = msg[hdr_size:]
            assert (msg_type == NNSocket.MSG_TYPE_PACKET_OUT)
            assert (len(msg) == length)
            return port_number, msg

        def send(self, port, pkt):
            pkt = str(pkt)
            msg = struct.pack("<iii%ds" % len(pkt), NNSocket.MSG_TYPE_PACKET_IN,
                              port, len(pkt), pkt)
            # because nnpy expects unicode when using str
            msg = list(msg)
            self.socket.send(msg)

        def close(self):
            self.socket.close()

        @staticmethod
        def get_socket(addr):
            NNSocket.lock.acquire()
            if addr not in NNSocket.nn_sockets:
                NNSocket.nn_sockets[addr] = NNSocket(addr)
                assert (addr not in NNSocket.nn_sockets_cnt)
                NNSocket.nn_sockets_cnt[addr] = 0
            nn_socket = NNSocket.nn_sockets[addr]
            NNSocket.nn_sockets_cnt[addr] += 1
            NNSocket.lock.release()
            return nn_socket

        @staticmethod
        def release_socket(addr):
            NNSocket.lock.acquire()
            NNSocket.nn_sockets_cnt[addr] -= 1
            if NNSocket.nn_sockets_cnt[addr] == 0:
                nn_socket = NNSocket.nn_sockets[addr]
                nn_socket.close()
                del NNSocket.nn_sockets_cnt[addr]
                del NNSocket.nn_sockets[addr]
            NNSocket.lock.release()

    class NNPortSocket:
        def __init__(self, iface, port):
            self.iface = iface
            self.nn_socket = NNSocket.get_socket(iface)
            self.port = port

        def send(self, pkt):
            self.nn_socket.send(self.port, pkt)

        def close(self):
            NNSocket.release_socket(self.iface)

    class NNListenSocket:
        def __init__(self, iface):
            self.iface = iface
            self.nn_socket = NNSocket.get_socket(iface)

        def fileno(self):
            return self.nn_socket.fileno()

        def close(self):
            NNSocket.release_socket(self.iface)

        def recv(self, ll = None):
            port, pkt = self.nn_socket.recv()
            if pkt is None:
                return None
            if ll is None:
                return port, pkt
            pkt = ll(pkt)
            pkt.time = time.time()
            return port, pkt

    conf.NNsocket = NNPortSocket
    conf.NNlisten = NNListenSocket

    break
