import logging
from collections import defaultdict
from typing import Callable

from cachetools import TTLCache
from google.protobuf.message import Message

from star_resonance_tracer.frame import Frame
from star_resonance_tracer.msg import Msg, CallMsg, NotifyMsg, ReturnMsg
from star_resonance_tracer.processor import process_frame

logger = logging.getLogger(__name__)

__all__ = (
    "Sniffer",
)


class Subscriber[T](list[Callable[[T], None]]):
    def publish(self, t: T) -> int:
        i = 0
        for i, cb in enumerate(self, start=1):
            cb(t)
        return i


class Sniffer:
    def __init__[T: Message, K: Message](self):
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

    def process_packet(self, payload: bytes):
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
