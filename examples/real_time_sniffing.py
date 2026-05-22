# /// script
# dependencies = [
#   "scapy>=2.7.0"
# ]
# ///

from collections import defaultdict

from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff

from star_resonance_tracer.connection import SignatureBasedConnectionDetector, Connection
from star_resonance_tracer.sniffer import Sniffer
from star_resonance_tracer.utils import TCPReassembler

conf.layers.filter([TCP, IP])

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.on_frame(lambda frame: print(frame))
    sniffer.on_message(lambda msg: print(msg))

    detector = SignatureBasedConnectionDetector()
    reassemblers: dict[Connection, TCPReassembler] = defaultdict(TCPReassembler)


    def on_packet(packet: Packet) -> None:
        if TCP not in packet or Raw not in packet:
            return

        tcp = packet[TCP]
        ip = packet[IP]

        connection = Connection.from_tuple(ip.src, tcp.sport, ip.dst, tcp.dport)
        payload = bytes(packet[Raw])

        # Check if packet is from bpsr
        if not detector.is_server(connection) and not detector.detect(connection, payload):
            return

        # Reassemble tcp fragment
        payload = reassemblers[connection].push(tcp.seq, payload)
        if not payload:
            return

        sniffer.process_packet(payload)


    sniff(filter="tcp and ip", prn=on_packet, store=False)
