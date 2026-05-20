from base64 import b64decode
from tomllib import load

from zstandard.backend_c import ZstdError

from star_resonance_tracer.sniffer import Sniffer, ServerPort, Connection

with open("tcp_stream.toml", "rb") as fp:
    TCP_STREAM = load(fp)

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.on_frame(lambda frame: print(frame))
    sniffer.on_message(lambda msg: print(msg))

    peers = [
        ServerPort(peer["host"], peer["port"])
        for peer in TCP_STREAM["peers"]
    ]
    sniffer.add_connection(Connection(peers[0], peers[1]))
    sniffer.add_connection(Connection(peers[1], peers[0]))

    for packet in TCP_STREAM["packets"]:
        peer: int = packet["peer"]
        connection = Connection(peers[peer], peers[(peer + 1) % 2])
        payload = b64decode(packet["data"])

        try:
            sniffer.process_packet(connection, payload)
        except ZstdError, ValueError:
            print("packet malformed")

        print()
