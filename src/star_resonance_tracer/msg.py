from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import override, Iterable

import zstandard

from star_resonance_tracer.frame import Frame
from star_resonance_tracer.utils import BinaryReader

MAX_ZSTD_BUFFER = 1_000_000  # 1 MB

__all__ = (
    "Msg",
    "CallMsg",
    "NotifyMsg",
    "ReturnMsg",
    "EchoMsg",
    "FrameUpMsg",
    "FrameDownMsg"
)


class Msg(ABC):
    @classmethod
    @abstractmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False):
        raise NotImplementedError


def extract_frames(data: bytes) -> Iterable[Frame]:
    reader = BinaryReader(data)
    while reader.remaining:
        length = reader.peek_u32()
        yield Frame.from_raw(reader.read(length))


@dataclass(slots=True, frozen=True)
class CallMsg(Msg):
    service_uuid: int
    stub_id: int
    call_id: int
    method_id: int
    data: bytes

    @override
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False):
        reader = BinaryReader(data)
        return cls(
            service_uuid=reader.read_u64(),
            stub_id=reader.read_u32(),
            call_id=reader.read_u32(),
            method_id=reader.read_u32(),
            data=zstandard.decompress(reader.read(), MAX_ZSTD_BUFFER) if zstd else reader.read()
        )


@dataclass(slots=True, frozen=True)
class NotifyMsg(Msg):
    service_uuid: int
    stub_id: int
    method_id: int
    data: bytes

    @override
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False):
        reader = BinaryReader(data)
        return cls(
            service_uuid=reader.read_u64(),
            stub_id=reader.read_u32(),
            method_id=reader.read_u32(),
            data=zstandard.decompress(reader.read(), MAX_ZSTD_BUFFER) if zstd else reader.read()
        )


@dataclass(slots=True, frozen=True)
class ReturnMsg(Msg):
    stub_id: int
    call_id: int
    error_id: int
    data: bytes

    @override
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False):
        reader = BinaryReader(data)
        return cls(
            stub_id=reader.read_u32(),
            call_id=reader.read_u32(),
            error_id=reader.read_u32(),
            data=zstandard.decompress(reader.read(), MAX_ZSTD_BUFFER) if zstd else reader.read()
        )


@dataclass(slots=True, frozen=True)
class EchoMsg(Msg):
    @override
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False):
        assert len(data) == 0
        return cls()


@dataclass(slots=True, frozen=True)
class FrameUpMsg(Msg):
    client_sequence: int
    data: bytes

    @override
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False):
        reader = BinaryReader(data)
        return cls(
            client_sequence=reader.read_u32(),
            data=zstandard.decompress(reader.read(), MAX_ZSTD_BUFFER) if zstd else reader.read()
        )

    @property
    def nested_frames(self) -> Iterable[Frame]:
        return extract_frames(self.data)


@dataclass(slots=True, frozen=True)
class FrameDownMsg(Msg):
    server_sequence: int
    data: bytes

    @override
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False):
        reader = BinaryReader(data)
        return cls(
            server_sequence=reader.read_u32(),
            data=zstandard.decompress(reader.read(), MAX_ZSTD_BUFFER) if zstd else reader.read()
        )

    @property
    def nested_frames(self) -> Iterable[Frame]:
        return extract_frames(self.data)
