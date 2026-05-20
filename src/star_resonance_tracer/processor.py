from typing import Iterator

from star_resonance_tracer.frame import *
from star_resonance_tracer.msg import *

__all__ = (
    "process_frame",
    "process_bytes"
)


def process_frame(frame: Frame) -> Iterator[Msg]:
    match frame.type:
        case MsgType.CALL:
            yield CallMsg.from_raw(frame.data, zstd=frame.compression == Compression.ZSTD)

        case MsgType.NOTIFY:
            yield NotifyMsg.from_raw(frame.data, zstd=frame.compression == Compression.ZSTD)

        case MsgType.RETURN:
            yield ReturnMsg.from_raw(frame.data, zstd=frame.compression == Compression.ZSTD)

        case MsgType.FRAME_UP | MsgType.FRAME_DOWN:
            msg: FrameUpMsg | FrameDownMsg
            if frame.type == MsgType.FRAME_UP:
                msg = FrameUpMsg.from_raw(frame.data, zstd=frame.compression == Compression.ZSTD)
            else:
                msg = FrameDownMsg.from_raw(frame.data, zstd=frame.compression == Compression.ZSTD)

            for frame in msg.nested_frames:
                yield from process_frame(frame)

        case _:
            pass


def process_bytes(data: bytes) -> Iterator[Msg]:
    return process_frame(Frame.from_raw(data))
