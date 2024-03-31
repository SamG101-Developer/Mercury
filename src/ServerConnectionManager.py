import time, os
from ipaddress import IPv6Address

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.exceptions import InvalidSignature

from src.ConnectionManager import ConnectionManager
from src.ConnectionProtocol import ConnectionProtocol
from src.Crypto import *


class ServerConnectionManager(ConnectionManager):
    _secret_key: rsa.RSAPrivateKey
    _public_key: rsa.RSAPublicKey
    _node_ips: dict[bytes, IPv6Address]  # ID -> IP
    _node_pub_keys: dict[bytes, bytes]   # ID -> Public key
    _message_queue: dict[bytes, dict[bytes, tuple[bytes, bytes]]]  # ID -> {message_id -> (sender, message)}

    def __init__(self):
        super().__init__()

        # Initialize the attributes.
        self._node_ips = {}

        # Either load the key pair from disk or generate a new one.
        if not os.path.exists("src/_my_keys/private_key.pem"):
            self._generate_and_serialize_key_pair()
        else:
            self._load_key_pair()

    def _generate_and_serialize_key_pair(self) -> None:
        # Generate a new secret and public key pair.
        self._secret_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._secret_key.public_key()

        # Serialize the keys to PEM format and write them to disk.
        secret_pem = self._secret_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        public_pem = self._public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.PKCS1)
        open("private_key.pem", "wb").write(secret_pem)
        open("public_key.pem", "wb").write(public_pem)

    def _load_key_pair(self) -> None:
        # Load the secret and public key from disk.
        secret_pem = open("private_key.pem", "rb").read()
        public_pem = open("public_key.pem", "rb").read()
        self._secret_key = load_pem_private_key(secret_pem, password=None)
        self._public_key = load_pem_public_key(public_pem)

    def _handle_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes) -> None:
        match command:
            # When a client registers to the application with a username.
            case ConnectionProtocol.REGISTER:
                self._handle_client_register(addr, data)

            # When a client comes online, it notifies the server.
            case ConnectionProtocol.CLIENT_ONLINE:
                self._handle_client_online(addr, data)

            # When a client wants to message another client for the first time.
            case ConnectionProtocol.SOLO_INVITE:
                self._handle_solo_invite_to_another_node(addr, data)

            # When a client sends a message to another (individual) client.
            case ConnectionProtocol.SEND_MESSAGE:
                self._handle_send_message(addr, data)

            # When a client wants to create a group chat.
            case ConnectionProtocol.CREATE_GC:
                ...

            # When a client has confirmed the group chat creation.
            case ConnectionProtocol.GC_CONFIRM:
                ...

            # When a client has acknowledged either an individual or group message.
            case ConnectionProtocol.MESSAGE_ACK:
                self._handle_message_ack(addr, data)

            # When a client receives an error.
            case ConnectionProtocol.ERROR:
                ...

            # Unknown
            case _:
                print(f"Unknown command: {command}")
                print(f"Data: {data}")

    def _handle_client_register(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into the node's IP address, ID (username), and public key.
        node_ip = addr.exploded
        node_username = data[:DIGEST_SIZE]
        node_public_key = load_pem_public_key(data[DIGEST_SIZE:]).public_bytes_raw()
        print(f"Registering {node_username} with IP {node_ip}")

        # Check the username doesn't already exist.
        if node_username in self._node_ips:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Username already exists.")
            return

        # Create the certificate for the node.
        certificate_raw = node_username + node_public_key
        certificate_sig = self._secret_key.sign(certificate_raw)
        self._node_pub_keys[node_username] = node_public_key
        print(f"\tGenerated certificate for {node_username}")

        # Send the certificate to the node.
        certificate = certificate_sig + certificate_raw
        self._send_command(ConnectionProtocol.REGISTER_ACK_AND_CERT, addr, certificate)

    def _handle_client_online(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into node's certificate and random signature.
        certificate_sig = data[:114]
        certificate_raw = data[114:228]
        challenge_sig = data[228:342]
        challenge_raw = data[342:]

        # Verify the certificate is valid.
        try:
            self._public_key.verify(certificate_sig, certificate_raw)
            client_username = certificate_raw[:DIGEST_SIZE]
            client_public_key = certificate_raw[DIGEST_SIZE:]
        except InvalidSignature:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Invalid certificate.")
            return

        # Use the signature to verify the client's identity.
        try:
            client_public_key.verify(challenge_sig, challenge_raw)
            assert time.time() - int.from_bytes(challenge_raw, "big") < 60
        except InvalidSignature:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Invalid challenge signature.")
            return
        except AssertionError:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Challenge expired.")
            return

        # Store the client's IP address, and send an acknowledegment.
        self._node_ips[client_username] = addr
        self._send_command(ConnectionProtocol.CLIENT_ONLINE_ACK, addr, b"")

        # If the client has messages in the queue, send them.
        if client_username in self._message_queue:
            for message_id, message_info in self._message_queue[client_username].items():
                message_sender, encrypted_message = message_info
                self._send_command(ConnectionProtocol.SEND_MESSAGE, addr, message_id + message_sender + encrypted_message)

    def _handle_solo_invite_to_another_node(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into the recipient's username and the message.
        recipient_username = data[:DIGEST_SIZE]

        # Check if the recipient exists / is online.
        if recipient_username not in self._node_ips:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Recipient is not online.")
            return

        # Send the invite to the recipient.
        recipient_addr = self._node_ips[recipient_username]
        sender_username = [k for k, v in self._node_ips.items() if v == addr][0]
        sender_public_key = self._node_pub_keys[sender_username]
        sender_ip_address = addr.packed
        self._send_command(ConnectionProtocol.PREP_FOR_SOLO, recipient_addr, sender_username + sender_public_key + sender_ip_address)

    def _handle_send_message(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into the recipient's username and the encrypted_message.
        recipient_username = data[:DIGEST_SIZE]
        encrypted_message = data[DIGEST_SIZE:]
        sender_username = [k for k, v in self._node_ips.items() if v == addr][0]

        # Check if the recipient exists / is online.
        message_id = HASH_ALGORITHM(str(time.time()).encode() + encrypted_message).digest()
        self._message_queue[recipient_username][message_id] = (sender_username, encrypted_message)

        # Send the encrypted_message to the recipient.
        if recipient_username in self._node_ips:
            recipient_addr = self._node_ips[recipient_username]
            self._send_command(ConnectionProtocol.SEND_MESSAGE, recipient_addr, message_id + sender_username + encrypted_message)

    def _handle_message_ack(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into the sender's username and the message_id.
        sender_username = [k for k, v in self._node_ips.items() if v == addr][0]
        message_id = data

        # Remove the message from the queue.
        self._message_queue[sender_username].pop(message_id)
