import array
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

import scapy.all


# flake8: noqa
class TCPPacket:
    def __init__(self, src_host, src_port, dst_host, dst_port, flags=0):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.flags = flags

    def build(self):
        packet = struct.pack(
            "!HHIIBBHHHBBHBBBBIIB3B",
            # PACKET:
            self.src_port,  #   Source Port
            self.dst_port,  #   Destination Port
            scapy.all.RandInt(),  #   Sequence Number
            0x00,  #   Acknoledgement Number
            10 << 4,  #   Data Offset
            self.flags,  #   Flags
            64240,  #   Window
            0x00,  #   Checksum (initial value)
            0x00,  #   Urgent pointer
            # OPTIONS:
            0x02,  #   MSS option:
            0x04,  #       Length
            1460,  #       Default MSS len
            0x04,  #   SACK Permitted option:
            0x02,  #     Length
            0x08,  #   Timestamp option:
            0x0A,  #     Length
            int(
                str(int(time.time() * 1000))[5:]
            ),  #     Timestamp value (current machine time)
            0x00,  #     Timestamp echo reply (initial value)
            0x01,  #   NOP
            0x03,  #   Window scale option:
            0x03,  #     Length
            0x07,  #     Shift count
        )

        pseudo_header = struct.pack(
            "!4s4sHH",
            socket.inet_aton(self.src_host),  # Source Address
            socket.inet_aton(self.dst_host),  # Destination Address
            0x06,  # Protocol ID
            len(packet),  # TCP Length
        )

        checksum = self.cheksum(pseudo_header + packet)

        packet = packet[:16] + struct.pack("H", checksum) + packet[18:]

        return packet

    def cheksum(self, packet):
        if len(packet) % 2 != 0:
            packet += b"\0"
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xFFFF)
        res += res >> 16
        return (~res) & 0xFFFF


def scan_port_syn(port: int):
    dst = "192.168.1.148"
    bind_port = scapy.all.RandShort()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.bind(("172.26.181.95", bind_port))
    s.settimeout(1)
    pak = TCPPacket("172.26.181.95", bind_port, dst, port, 0b000000010)
    s.sendto(pak.build(), (dst, 0))
    data = s.recv(1024)
    if len(data) >= 33 and data[33] == 18:
        open_port = data[20] * 256 + data[21]
        print(f"{open_port = }")

    s.close()


with ThreadPoolExecutor(max_workers=10) as executor:
    for port in range(100):
        executor.submit(scan_port_syn, port)
