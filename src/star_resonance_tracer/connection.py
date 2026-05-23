import logging
from dataclasses import dataclass
from socket import AddressFamily
from typing import Protocol, override, ClassVar

import psutil

__all__ = (
    "Endpoint",
    "Connection",
    "ConnectionDetector",
    "CachedConnectionDetector",
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
    def is_server(self, connection: Connection) -> bool:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError

    def as_bpf_filter(self) -> str:
        raise NotImplementedError


class CachedConnectionDetector(ConnectionDetector):
    def __init__(self):
        self._endpoints: set[Endpoint] = set()

    @override
    def is_server(self, connection: Connection) -> bool:
        return connection.src in self._endpoints or connection.dst in self._endpoints

    @override
    def reset(self) -> None:
        self._endpoints.clear()

    @override
    def as_bpf_filter(self) -> str:
        def _and(*conds: str) -> str:
            return " and ".join(f"({cond})" for cond in conds if cond)

        def _or(*conds: str) -> str:
            return " or ".join(f"({cond})" for cond in conds if cond)

        return _and(
            "tcp[tcpflags] & (tcp-push) != 0",
            _or(
                *(_and(f"host {endpoint.ip}", f"port {endpoint.port}") for endpoint in self._endpoints)
            )
        )


class PidBasedConnectionDetector(CachedConnectionDetector):
    def add_from_executable_name(self, executable_name: str) -> int:
        for proc in psutil.process_iter():
            if proc.name().startswith(executable_name):
                return self.add_from_pid(proc.pid)
        return 0

    def add_from_pid(self, pid: int) -> int:
        count = 0
        for conn in psutil.net_connections(kind="tcp4"):
            if conn.pid != pid:
                continue

            if not conn.laddr or not conn.raddr:
                continue

            if "127.0.0.1" in conn.laddr.ip or "127.0.0.1" in conn.raddr.ip:
                continue

            self._endpoints.add(Endpoint(conn.raddr.ip, conn.raddr.port))
            logger.info(f"Detected server ip {conn.raddr.ip}:{conn.raddr.port}")
            count += 1
        return count


class SignatureBasedConnectionDetector(CachedConnectionDetector):
    ECHO_SIGNATURE: ClassVar[bytes] = bytes.fromhex("00 00 00 06 00 04")

    def __init__(self):
        super().__init__()

        self.local_ips: set[str] = set()
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == AddressFamily.AF_INET:
                    self.local_ips.add(addr.address)

    def detect(self, connection: Connection, payload: bytes) -> bool:
        if self.is_server(connection):
            return True

        if payload.startswith(self.ECHO_SIGNATURE):
            self._endpoints.add(connection.src if connection.src.ip not in self.local_ips else connection.dst)
            return True

        return False


class ManualConnectionDetector(CachedConnectionDetector):
    def add_endpoint(self, endpoint: Endpoint) -> None:
        self._endpoints.add(endpoint)
