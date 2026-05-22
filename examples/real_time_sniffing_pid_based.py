# /// script
# dependencies = [
#   "scapy>=2.7.0"
# ]
# ///

from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff

from star_resonance_tracer.connection import PidBasedConnectionDetector, Connection
from star_resonance_tracer.sniffer import Sniffer

conf.layers.filter([TCP, IP])

if __name__ == '__main__':
    detector = PidBasedConnectionDetector()
    while True:
        detected = detector.add_from_pid(int(input("Program PID: ")))
        if detected:
            break
        print("No TCP connection found")

    sniffer = Sniffer(detector)
    sniffer.on_frame(lambda frame: print(frame))
    sniffer.on_message(lambda msg: print(msg))


    def on_packet(packet: Packet) -> None:
        if TCP not in packet or Raw not in packet:
            return

        tcp = packet[TCP]
        ip = packet[IP]

        connection = Connection.from_tuple(ip.src, tcp.sport, ip.dst, tcp.dport)
        payload = bytes(packet[Raw])

        sniffer.process_packet(connection, payload, tcp_sequence=tcp.seq)


    sniff(filter="tcp and ip", prn=on_packet, store=False)
