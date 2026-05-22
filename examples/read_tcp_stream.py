from base64 import b64decode
from tomllib import load

from zstandard.backend_c import ZstdError

from star_resonance_tracer.sniffer import Sniffer

with open("tcp_stream.toml", "rb") as fp:
    TCP_STREAM = load(fp)

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.on_frame(lambda frame: print(frame))
    sniffer.on_message(lambda msg: print(msg))

    for packet in TCP_STREAM["packets"]:
        peer: int = packet["peer"]

        payload = b64decode(packet["data"])

        try:
            sniffer.process_packet(payload)
        except ZstdError, ValueError:
            print("packet malformed")

        print()
