from abc import ABC, abstractmethod
from ipaddress import IPv6Address
from threading import Thread
import socket

from src.ConnectionProtocol import ConnectionProtocol


class ConnectionManager(ABC):
    _server_socket: socket.socket

    def __init__(self):
        # Create the IPv6 socket
        self._server_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._server_socket.bind(("::", 5000))
        Thread(target=self._listen).start()

    def _listen(self) -> None:
        while True:
            data, addr = self._server_socket.recvfrom(1024)
            command = ConnectionProtocol(data[0])
            Thread(target=self._handle_command, args=(command, addr, data[1:])).start()

    @abstractmethod
    def _handle_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes) -> None:
        ...

    def _send_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes) -> None:
        data = command.value.to_bytes(1, "big") + data
