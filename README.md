star-resonance-tracer-py
=========================

A Python library for handling and processing Blue Protocol: Star Resonance communication packets.

## API

### Frame and Messages

```python
# star_resonance_tracer.frame
class Frame:
    length: int
    compression: Compression
    type: MsgType
    data: bytes

    @classmethod
    def from_raw(cls, data: bytes): ...

    
# star_resonance_tracer.msg
class CallMsg(Msg):
    service_uuid: int
    stub_id: int
    call_id: int
    method_id: int
    data: bytes
    
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False): ...


class NotifyMsg(Msg):
    service_uuid: int
    stub_id: int
    method_id: int
    data: bytes

    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False): ...


class ReturnMsg(Msg):
    stub_id: int
    call_id: int
    error_id: int
    data: bytes

    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False): ...


class EchoMsg(Msg):
    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False): ...


class FrameUpMsg(Msg):
    client_sequence: int
    data: bytes

    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False): ...
    
    @property
    def nested_frames(self) -> Iterable[Frame]: ...


class FrameDownMsg(Msg):
    server_sequence: int
    data: bytes

    @classmethod
    def from_raw(cls, data: bytes, *, zstd: bool = False): ...

    @property
    def nested_frames(self) -> Iterable[Frame]: ...
```

### Processing

```python
# star_resonance_tracer.processor

# Lower level methods to directly parse byte payloads
def process_frame(frame: Frame) -> Iterator[Msg]: ...

def process_bytes(data: bytes) -> Iterator[Msg]: ...
```

### Sniffing

```python
# star_resonance_tracer.sniffer

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
2. Build
   ```bash
   uv build
   ```

## Examples

Refer to `./examples`.

## Disclaimer

This project is provided solely for technical research and combat data analysis. 

This project is in no form related, associated, or endorsed by the developer and publisher of Blue Protocol: Star
Resonance.
