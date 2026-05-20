star-resonance-tracer-py
=========================

A Python library for handling and processing Blue Protocol: Star Resonance communication packets.

## API

### Frame and Messages

```python
from star_resonance_tracer.frame import Compression, MsgType
from star_resonance_tracer.msg import Msg


class Frame:
    length: int
    compression: Compression
    type: MsgType
    data: bytes

    @classmethod
    def from_raw(cls, data: bytes): ...


class CallMsg(Msg):
    ...


class NotifyMsg(Msg):
    ...


class ReturnMsg(Msg):
    ...


class EchoMsg(Msg):
    ...


class FrameUpMsg(Msg):
    ...


class FrameDownMsg(Msg):
    ...
```

### Processing

```python
from typing import Iterator

from star_resonance_tracer.frame import *
from star_resonance_tracer.msg import *

# Lower level methods to directly parse byte payloads
def process_frame(frame: Frame) -> Iterator[Msg]: ...

def process_bytes(data: bytes) -> Iterator[Msg]: ...
```

### Sniffing

```python
from typing import Callable

from google.protobuf.message import Message

from star_resonance_tracer.frame import Frame
from star_resonance_tracer.msg import Msg
from star_resonance_tracer.sniffer import Connection


# High level utility to process stream of packets with callbacks
class Sniffer:
    # Configure service types and the associated protobuf message
    def set_service_type[T: Message](self, service_id: int, method_id: int, msg_type: type[T]) -> None: ...
    def set_return_type[T: Message, K: Message](self, call_type: type[T], return_type: type[K]) -> None: ...

    # Calls on a raw frame
    def on_frame(self, callback: Callable[[Frame], None]) -> Callable[[Frame], None]: ...

    # Calls for each message processed from a frame
    def on_message(self, callback: Callable[[Msg], None]) -> Callable[[Msg], None]: ...

    # Calls when message is one of the configured service and return types.
    def on_service[T: Message](self, msg_type: type[T], callback: Callable[[T], None]) -> Callable[[T], None]: ...

    # Utility function to process stream of packets, with features like
    # - finds connection with BPSR signature
    # - does TCP reassembly
    # - store call queue and process return message
    def process_packet(self, connection: Connection, payload: bytes, *, tcp_sequence: int | None = None): ...
```

## Building

1. Update git submodules.
   ```bash
   git submodule update --init --recursive
   ```
2. Generate BPSR protocol buffers.
   ```bash
   uv run --dev scripts/generate_protobufs.py
   ```
3. Build
   ```bash
   uv build
   ```

## Examples

Refer to `./examples`.

## Disclaimer

This project is provided solely for technical research and combat data analysis. 

This project is in no form related, associated, or endorsed by the developer and publisher of Blue Protocol: Star
Resonance.
