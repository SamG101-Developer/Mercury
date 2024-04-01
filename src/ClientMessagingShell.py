from base64 import b64decode
from threading import Thread
import socket, sys


READER_PORT = 20002


class Shell:
    _send_thread: Thread
    _recv_thread: Thread
    _writer_socket: socket.socket
    _recipient_id: bytes

    def __init__(self, port: int, who: str) -> None:
        # Convert the recipient's name to an ID.
        self._recipient_id = b64decode(who)

        # Create a socket and bind it to the writer port.
        self._writer_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._writer_socket.bind(('::1', port))

        # Start the send and receive threads.
        self._send_thread = Thread(target=self._send)
        self._recv_thread = Thread(target=self._recv)
        self._send_thread.start()
        self._recv_thread.start()

    def _send(self) -> None:
        while True:
            # Get a message from the user and send it.
            line = input("Message > ")
            line = self._recipient_id + line.encode()
            self._writer_socket.sendto(line, ('::1', READER_PORT))

    def _recv(self) -> None:
        while True:
            # Receive a message and decode it.
            line, _ = self._writer_socket.recvfrom(1024)
            line = line.decode()

            # Remove the current "Message > " prompt and print the message.
            sys.stdout.write('\r' + ' ' * (len(line) + len("Message > ")) + '\r')
            print(line, end='')
            sys.stdout.write("Message > ")
            sys.stdout.flush()

    def __del__(self) -> None:
        # Close the socket and join the threads.
        self._writer_socket.close()
        self._send_thread.join()
        self._recv_thread.join()


s = Shell(int(sys.argv[1]), sys.argv[2])
