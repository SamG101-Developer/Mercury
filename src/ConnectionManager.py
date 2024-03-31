from abc import ABC, abstractmethod
from ipaddress import IPv6Address
from threading import Thread
import socket

from src.ConnectionProtocol import ConnectionProtocol


class ConnectionManager(ABC):
    _server_socket: socket.socket

    def __init__(self, is_server: bool = False):
        # Create the IPv6 socket
        self._server_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._server_socket.bind(("::", 20001 if is_server else 20000))
        Thread(target=self._listen).start()

    def _listen(self) -> None:
        print("Listening for incoming connections...")
        while True:
            data, addr = self._server_socket.recvfrom(2048)
            command = ConnectionProtocol(data[0])
            addr = IPv6Address(addr[0])
            Thread(target=self._handle_command, args=(command, addr, data[1:])).start()

    @abstractmethod
    def _handle_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes) -> None:
        ...

    def _send_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes, to_server: bool = False) -> None:
        data = command.value.to_bytes(1, "big") + data
        port = 20000 if not to_server else 20001
        self._server_socket.sendto(data, (addr.exploded, port))
