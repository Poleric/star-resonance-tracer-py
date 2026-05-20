import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from cachetools import TTLCache
from google.protobuf.message import Message

from star_resonance_tracer.frame import Frame
from star_resonance_tracer.msg import Msg, CallMsg, NotifyMsg, ReturnMsg
from star_resonance_tracer.processor import process_frame
from star_resonance_tracer.utils import TCPReassembler

logger = logging.getLogger(__name__)

__all__ = (
    "ServerPort",
    "Connection",
    "Sniffer"
)


@dataclass(frozen=True, slots=True)
class ServerPort:
    ip: str
    port: int


@dataclass(frozen=True, slots=True)
class Connection:
    src: ServerPort
    dst: ServerPort

    @classmethod
    def from_tuple(cls, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        return cls(
            ServerPort(src_ip, src_port),
            ServerPort(dst_ip, dst_port)
        )


class Subscriber[T](list[Callable[[T], None]]):
    def publish(self, t: T) -> int:
        i = 0
        for i, cb in enumerate(self, start=1):
            cb(t)
        return i


class Sniffer:
    ECHO_SIGNATURE = bytes.fromhex("00 00 00 06 00 04")

    def __init__[T: Message, K: Message](self):
        self._reassemblers: dict[Connection, TCPReassembler] = defaultdict(TCPReassembler)
        self._calls: TTLCache[int, type[T]] = TTLCache(maxsize=32, ttl=60)

        self._service_types: dict[tuple[int, int], type[T]] = {}
        self._return_types: dict[type[K], type[T]] = {}

        self._on_frame: Subscriber[Frame] = Subscriber()  # noqa
        self._on_message: Subscriber[Msg] = Subscriber()  # noqa
        self._on_service: dict[type[T], Subscriber[T]] = defaultdict(Subscriber)

    def set_service_type[T: Message](self, service_id: int, method_id: int, msg_type: type[T]) -> None:
        self._service_types[(service_id, method_id)] = msg_type

    def set_return_type[T: Message, K: Message](self, call_type: type[T], return_type: type[K]) -> None:
        self._return_types[call_type] = return_type

    def on_frame(self, callback: Callable[[Frame], None]) -> Callable[[Frame], None]:
        self._on_frame.append(callback)
        return callback

    def on_message(self, callback: Callable[[Msg], None]) -> Callable[[Msg], None]:
        self._on_message.append(callback)
        return callback

    def on_service[T: Message](self, msg_type: type[T], callback: Callable[[T], None]) -> Callable[[T], None]:
        self._on_service[msg_type].append(callback)
        return callback

    def _is_server(self, payload: bytes) -> bool:
        return payload.startswith(self.ECHO_SIGNATURE)

    def add_connection(self, connection: Connection):
        _ = self._reassemblers[connection]

    def process_packet(self, connection: Connection, payload: bytes, *, tcp_sequence: int | None = None):
        if connection not in self._reassemblers:
            # Discover/lock server flow
            if self._is_server(payload):
                logger.info(f"Adding to flow "
                            f"{connection.src.ip}:{connection.src.port} <-> "
                            f"{connection.dst.ip}:{connection.dst.port}")
                self.add_connection(connection)
            else:
                return

        if tcp_sequence is not None:
            try:
                payload = self._reassemblers[connection].push(tcp_sequence, payload)
            except KeyError:
                return

        if not payload:
            return

        frame = Frame.from_raw(payload)
        self._on_frame.publish(frame)

        for msg in process_frame(frame):
            self._on_message.publish(msg)

            match msg:
                case CallMsg() | NotifyMsg():
                    msg_type = self._service_types.get((msg.service_uuid, msg.method_id))
                    if msg_type is None:
                        continue

                    if isinstance(msg, CallMsg):
                        self._calls[msg.call_id] = msg_type

                case ReturnMsg():
                    call_type = self._calls.get(msg.call_id)
                    if call_type is None:
                        continue

                    del self._calls[msg.call_id]

                    msg_type = self._return_types.get(call_type)
                    if msg_type is None:
                        continue

                case _:
                    continue

            msg_type: type[Message]
            self._on_service[msg_type].publish(msg_type.FromString(msg.data))
