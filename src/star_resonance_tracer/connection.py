import itertools
import logging
from dataclasses import dataclass
from typing import Protocol, override, ClassVar

import psutil

__all__ = (
    "Endpoint",
    "Connection",
    "ConnectionDetector",
    "PidBasedConnectionDetector",
    "SignatureBasedConnectionDetector",
    "ManualConnectionDetector"
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Endpoint:
    ip: str
    port: int


@dataclass(frozen=True, slots=True)
class Connection:
    src: Endpoint
    dst: Endpoint

    @classmethod
    def from_tuple(cls, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        return cls(
            Endpoint(src_ip, src_port),
            Endpoint(dst_ip, dst_port)
        )


class ConnectionDetector(Protocol):
    def is_server(self, connection: Connection, payload: bytes) -> bool:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError


class PidBasedConnectionDetector(ConnectionDetector):
    def __init__(self):
        self._connections: set[Connection] = set()

    def add_from_pid(self, pid: int) -> int:
        count = 0
        for conn in psutil.net_connections(kind="tcp4"):
            if conn.pid != pid:
                continue

            if not conn.laddr or not conn.raddr:
                continue

            if "127.0.0.1" in conn.laddr.ip or "127.0.0.1" in conn.raddr.ip:
                continue

            for src, dst in itertools.permutations((conn.laddr, conn.raddr)):
                logger.info(f"Detected flow "
                            f"{src.ip}:{src.port} <-> "
                            f"{dst.ip}:{dst.port}")
                self._connections.add(Connection.from_tuple(src.ip, src.port, dst.ip, dst.port))
                count += 1
        return count

    @override
    def is_server(self, connection: Connection, payload: bytes) -> bool:
        return connection in self._connections

    @override
    def reset(self) -> None:
        self._connections.clear()


class SignatureBasedConnectionDetector(ConnectionDetector):
    ECHO_SIGNATURE: ClassVar[bytes] = bytes.fromhex("00 00 00 06 00 04")

    def __init__(self):
        self._connections: set[Connection] = set()

    @override
    def is_server(self, connection: Connection, payload: bytes) -> bool:
        if connection in self._connections:
            return True

        if payload.startswith(self.ECHO_SIGNATURE):
            logger.info(f"Detected flow "
                        f"{connection.src.ip}:{connection.src.port} <-> "
                        f"{connection.dst.ip}:{connection.dst.port}")
            self._connections.add(connection)
            return True

        return False

    @override
    def reset(self) -> None:
        self._connections.clear()


class ManualConnectionDetector(ConnectionDetector):
    def __init__(self):
        self._connections: set[Connection] = set()

    def add_connection(self, connection: Connection) -> None:
        self._connections.add(connection)

    @override
    def is_server(self, connection: Connection, payload: bytes) -> bool:
        return connection in self._connections

    @override
    def reset(self) -> None:
        self._connections.clear()
