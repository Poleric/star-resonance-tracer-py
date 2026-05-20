from dataclasses import dataclass
from enum import Enum

from star_resonance_tracer.utils import BinaryReader

__all__ = (
    "Compression",
    "MsgType",
    "Frame"
)


class Compression(Enum):
    NONE = 0
    ZSTD = 0x80


class MsgType(Enum):
    NONE = 0
    CALL = 1
    NOTIFY = 2
    RETURN = 3
    ECHO = 4
    FRAME_UP = 5
    FRAME_DOWN = 6
    ACK_FRAME_UP = 7
    ACK_FRAME_DOWN = 8
    REWIND_FRAME = 9
    CALL_INNER = 10
    NOTIFY_INNER = 11
    BROADCAST = 12
    BROADCAST_BY_SES = 13
    TERMINATE = 14


@dataclass(slots=True, frozen=True)
class Frame:
    length: int
    compression: Compression
    type: MsgType
    data: bytes

    @classmethod
    def from_raw(cls, data: bytes):
        reader = BinaryReader(data)
        return cls(
            length=reader.read_u32(),
            compression=Compression(reader.read_u8()),
            type=MsgType(reader.read_u8()),
            data=reader.read()
        )
