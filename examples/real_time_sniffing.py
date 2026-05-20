# /// script
# dependencies = [
#   "scapy>=2.7.0"
# ]
# ///

from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff

from star_resonance_tracer.sniffer import Sniffer, Connection, ServerPort

conf.layers.filter([TCP, IP])

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.on_frame(lambda frame: print(frame))
    sniffer.on_message(lambda msg: print(msg))


    def on_packet(packet: Packet) -> None:
        if TCP not in packet or Raw not in packet:
            return

        tcp = packet[TCP]
        ip = packet[IP]

        connection = Connection(
            ServerPort(ip.src, tcp.sport),
            ServerPort(ip.dst, tcp.dport)
        )

        payload = bytes(packet[Raw])

        sniffer.process_packet(connection, payload, tcp_sequence=tcp.seq)


    sniff(filter="tcp and ip", prn=on_packet, store=False)
