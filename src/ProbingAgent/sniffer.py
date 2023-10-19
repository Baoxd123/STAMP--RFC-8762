#!/usr/bin/env python

'''
This script is based on https://gist.github.com/gteissier/4e076b2645e1754c99c8278cd4a6a987
'''

import socket
import ctypes
from struct import pack
import sys
import mmap
import select
from threading import Thread

from scapy.arch.linux import attach_filter
from scapy.all import Ether


class Const(object):
    ETH_P_ALL = 0x0003
    ETH_P_IP = 0x0800
    IFF_PROMISC = 0x100
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    SO_ATTACH_FILTER = 26

    SOCK_NONBLOCK = 0x800
    SOL_PACKET = 263
    PACKET_RX_RING = 5

    PACKET_HOST = 0  # To us
    PACKET_BROADCAST = 1  # To all
    PACKET_MULTICAST = 2  # To group
    PACKET_OTHERHOST = 3  # To someone else
    PACKET_OUTGOING = 4  # Outgoing
    PACKET_USER = 6  # To userspace
    PACKET_KERNEL = 7  # To kernel

    PAGESIZE = 4096

    TP_STATUS_KERNEL = 0
    TP_STATUS_USER = 1


class tpacket_req(ctypes.Structure):
    _fields_ = [
        ('tp_block_size', ctypes.c_uint),  # Minimal size of contiguous block
        ('tp_block_nr', ctypes.c_uint),    # Number of blocks
        ('tp_frame_size', ctypes.c_uint),  # Size of frame
        ('tp_frame_nr', ctypes.c_uint),    # Total number of frames
    ]


class tpacket_hdr(ctypes.Structure):
    _fields_ = [
        ('tp_status', ctypes.c_ulong),
        ('tp_len', ctypes.c_uint),
        ('tp_snaplen', ctypes.c_uint),
        ('tp_mac', ctypes.c_ushort),
        ('tp_net', ctypes.c_ushort),
        ('tp_sec', ctypes.c_uint),
        ('tp_usec', ctypes.c_uint),
    ]


class Sniffer(object):
    def __init__(self, nr_frames=4096, iface=None, filter=None):
        # Check number of frames is a power of 2
        assert(nr_frames & (nr_frames-1) == 0)

        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW |
                          Const.SOCK_NONBLOCK, socket.htons(Const.ETH_P_ALL))
        assert(s is not None and s != -1)

        # Attach BPF filter
        if filter is not None:
            attach_filter(sock=s, bpf_filter=filter, iface=iface)

        if iface is not None:
            s.bind((iface, Const.ETH_P_ALL))

        # Create packets ring buffer
        tp = tpacket_req()
        tp.tp_block_size = nr_frames * Const.PAGESIZE
        tp.tp_block_nr = 1
        tp.tp_frame_size = Const.PAGESIZE
        tp.tp_frame_nr = nr_frames
        self.nr_frames = nr_frames

        s.setsockopt(Const.SOL_PACKET, Const.PACKET_RX_RING, tp)

        self.sock = s

        # Map packets ring buffer
        self.ringbuffer = mmap.mmap(s.fileno(), tp.tp_frame_size*tp.tp_frame_nr,
                                    mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        self.offset = 0

    def recv_packets(self):
        while True:
            hdr = tpacket_hdr.from_buffer(
                self.ringbuffer, self.offset*Const.PAGESIZE)
            if (hdr.tp_status & Const.TP_STATUS_USER) == 0:
                break

            pkt_offset = self.offset*Const.PAGESIZE + hdr.tp_mac
            pkt_length = hdr.tp_snaplen

            yield ((hdr.tp_sec, hdr.tp_usec), self.ringbuffer[pkt_offset:pkt_offset+pkt_length])

            hdr.tp_status = Const.TP_STATUS_KERNEL
            self.offset += 1

            # should be a modulo, but we required to have a power of two
            # in this case, &= (self.nr_frames - 1) is equivalent to %= self.nr_frames
            self.offset &= (self.nr_frames - 1)


def dump_pkt(pkt, ts):
    (tv_sec, tv_usec) = ts
    print("%5d.%5d\t%s" % (tv_sec, tv_usec, Ether(pkt).summary()))


class AsyncSniffer:
    def __init__(self, nr_frames=4096, iface=None, filter=None, prn=None):
        self.thread = None
        self.sniffer = Sniffer(nr_frames, iface, filter)
        self.stop_sniff = False
        self.prn = prn if prn is not None else dump_pkt

    def _run(self):
        poller = select.poll()
        poller.register(self.sniffer.sock, select.POLLIN)
        #print('start sniff')
        while not self.stop_sniff:
            events = poller.poll(500)
            for (fd, evt) in events:
                #print('event')
                assert(fd == self.sniffer.sock.fileno())
                assert(evt == select.POLLIN)

                for (ts, pkt) in self.sniffer.recv_packets():
                    self.prn(pkt, ts)
            #print('polling')
        #print('stopped sniff')

    def _setup_thread(self):
        self.thread = Thread(
            target=self._run,
            name="AsyncSniffer"
        )
        self.thread.daemon = True
        #print('start thread')

    def start(self):
        """Starts AsyncSniffer in async mode"""
        self._setup_thread()
        if self.thread:
            self.thread.start()

    def stop(self):
        self.stop_sniff = True


def sniff(*args, **kwargs):
    sniffer = AsyncSniffer()
    sniffer._run(*args, **kwargs)


if __name__ == '__main__':
    n_packets = 0

    with open(sys.argv[1], 'wb') as f:
        # libpcap file format, tcpdump 2.4
        f.write(pack('!IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1))

        s = Sniffer(nr_frames=4096, iface=sys.argv[1])

        poller = select.poll()
        poller.register(s.sock, select.POLLIN)

        while True:
            events = poller.poll(500)
            for (fd, evt) in events:
                assert(fd == s.sock.fileno())
                assert(evt == select.POLLIN)

                for (ts, pkt) in s.recv_packets():
                    (tv_sec, tv_usec) = ts

                    f.write(pack('!IIII', tv_sec, tv_usec, len(pkt), len(pkt)))
                    f.write(pkt)

                    n_packets += 1

            f.flush()
            sys.stdout.write('\r captured %06d packets' % n_packets)
            sys.stdout.flush()
