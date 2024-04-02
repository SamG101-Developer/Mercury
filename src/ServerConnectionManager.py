import json, time, os
from ipaddress import IPv6Address
from threading import Lock
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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
    _node_certs: dict[bytes, bytes]      # ID -> Certificate
    _message_queue: dict[bytes, dict[bytes, tuple[bytes, bytes]]]  # ID -> {message_id -> (sender, message)}
    _groups_multicast_addresses: dict[bytes, IPv6Address]  # ID -> Multicast address

    JSON_LOCK = Lock()

    def __init__(self):
        super().__init__(is_server=True)

        # Initialize the attributes.
        self._secret_key = None
        self._public_key = None
        self._node_ips = {}
        self._node_pub_keys = {}
        self._node_certs = {}
        self._message_queue = {}
        self._groups_multicast_addresses = {}

        # Either load the key pair from disk or generate a new one.
        if not os.path.exists("src/_server_keys"):
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
        os.mkdir("src/_server_keys")
        open("src/_server_keys/private_key.pem", "wb").write(secret_pem)
        open("src/_server_keys/public_key.pem", "wb").write(public_pem)
        open("src/_server_keys/node_info.json", "w").write("{}")

    def _load_key_pair(self) -> None:
        # Load the secret and public key from disk.
        secret_pem = open("src/_server_keys/private_key.pem", "rb").read()
        public_pem = open("src/_server_keys/public_key.pem", "rb").read()
        node_info = json.load(open("src/_server_keys/node_info.json"))

        self._secret_key = load_pem_private_key(secret_pem, password=None)
        self._public_key = load_pem_public_key(public_pem)

        with ServerConnectionManager.JSON_LOCK:
            self._node_pub_keys = {b64decode(k): b64decode(v["public_key"]) for k, v in node_info.items()}
            self._node_certs = {b64decode(k): b64decode(v["certificate"]) for k, v in node_info.items()}

    def _handle_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes) -> None:
        match command:
            # When a client registers to the application with a username.
            case ConnectionProtocol.REGISTER:
                self._handle_client_register(addr, data)

            # When a client comes online, it notifies the server.
            case ConnectionProtocol.CLIENT_ONLINE:
                self._handle_client_online(addr, data)

            # When a client wants to message another client for the first time.
            case ConnectionProtocol.GET_NODE_INFO:
                self._handle_get_node_info(addr, data)

            # When a client wants a list of IPs to invite to a group.
            case ConnectionProtocol.GC_IP_REQUEST:
                self._handle_gc_ip_request(addr, data)

            # When a client sends a message to another (individual) client.
            case ConnectionProtocol.SEND_MESSAGE:
                self._handle_send_message(addr, data)

            # When a client wants to create a group chat.
            case ConnectionProtocol.CREATE_GC:
                self._handle_create_a_group_chat(addr, data)

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
        node_public_key = data[DIGEST_SIZE:]
        print(f"Registering {node_username} with IP {node_ip}")

        # Check the username doesn't already exist.
        if node_username in self._node_ips:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Username already exists.")
            return

        # Create the certificate for the node.
        certificate_raw = node_username + node_public_key
        certificate_sig = self._secret_key.sign(
            data=certificate_raw,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            algorithm=hashes.SHA256())

        self._node_pub_keys[node_username] = node_public_key
        self._node_certs[node_username]    = certificate_sig + certificate_raw
        print(f"\tGenerated certificate for {node_username}")

        # Add the node to the json list of nodes.
        with ServerConnectionManager.JSON_LOCK:
            # todo: prevent double-registering
            saved_node_info = json.load(open("src/_server_keys/node_info.json"))
            saved_node_info[b64encode(node_username).decode()] = {
                "public_key": b64encode(node_public_key).decode(),
                "certificate": b64encode(certificate_sig + certificate_raw).decode(),
            }
            json.dump(saved_node_info, open("src/_server_keys/node_info.json", "w"))

        # Send the certificate to the node.
        certificate = certificate_sig + certificate_raw
        self._send_command(ConnectionProtocol.REGISTER_ACK_AND_CERT, addr, certificate)

    def _handle_client_online(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into node's certificate and random signature.
        certificate_sig = data[:RSA_SIGNATURE_SIZE]
        certificate_raw = data[RSA_SIGNATURE_SIZE:RSA_SIGNATURE_SIZE + RSA_CERTIFICATE_SIZE]
        challenge_sig = data[RSA_SIGNATURE_SIZE + RSA_CERTIFICATE_SIZE:RSA_SIGNATURE_SIZE * 2 + RSA_CERTIFICATE_SIZE]
        challenge_raw = data[RSA_SIGNATURE_SIZE * 2 + RSA_CERTIFICATE_SIZE:]

        # Verify the certificate is valid.
        try:
            self._public_key.verify(
                signature=certificate_sig,
                data=certificate_raw,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())

            client_username = certificate_raw[:DIGEST_SIZE]
            client_public_key = certificate_raw[DIGEST_SIZE:]
        except InvalidSignature:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Invalid certificate.")
            return

        # Use the signature to verify the client's identity.
        try:
            client_public_key = load_pem_public_key(client_public_key)
            client_public_key.verify(
                signature=challenge_sig,
                data=challenge_raw,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())
            assert time.time() - int.from_bytes(challenge_raw, "big") < 60
        except InvalidSignature:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Invalid challenge signature.")
            return
        except AssertionError:
            self._send_command(ConnectionProtocol.ERROR, addr, b"Challenge expired.")
            return

        # Store the client's IP address, and send an acknowledgement.
        self._node_ips[client_username] = addr
        self._send_command(ConnectionProtocol.CLIENT_ONLINE_ACK, addr, b"")
        print(f"{client_username} is online ({addr}).")

        # If the client has messages in the queue, send them.
        if client_username in self._message_queue:
            for message_id, message_info in self._message_queue[client_username].copy().items():
                message_sender, encrypted_message = message_info
                self._send_command(ConnectionProtocol.SEND_MESSAGE, addr, message_id + message_sender + encrypted_message)
        else:
            self._message_queue[client_username] = {}

    def _handle_get_node_info(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into the recipient's username and the message.
        recipient_id = data[:DIGEST_SIZE]

        # Check if the recipient exists / is online.
        if recipient_id not in self._node_ips:
            self._send_command(ConnectionProtocol.ERROR, addr, f"Recipient {recipient_id} is not online.".encode())
        else:
            self._send_command(ConnectionProtocol.NODE_INFO, addr, self._node_certs[recipient_id] + self._node_ips[recipient_id].packed)

    def _handle_gc_ip_request(self, addr: IPv6Address, data: bytes) -> None:
        # todo: needs auth from server

        # Split the data into the recipients' IDs.
        recipient_ids = data.split(b" ")
        ip_addresses = {}

        # Check if the recipients exist / are online.
        for recipient_id in recipient_ids:
            if recipient_id not in self._node_ips:
                self._send_command(ConnectionProtocol.ERROR, addr, f"Recipient {recipient_id} is not online.".encode())
                return
            ip_addresses[recipient_id] = self._node_ips[recipient_id]

        # Send the IP addresses to the client.
        sending_data = json.dumps(ip_addresses).encode()
        print("Sending IP addresses to client: ", sending_data)
        self._send_command(ConnectionProtocol.GC_NODE_INFO, addr, sending_data)

    def _handle_send_message(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into the recipient's username and the encrypted_message.
        recipient_id = data[:DIGEST_SIZE]
        encrypted_message = data[DIGEST_SIZE:]
        sender_id = [k for k, v in self._node_ips.items() if v == addr][0]

        # Queue the message for the recipient.
        message_id = HASH_ALGORITHM(str(time.time()).encode() + encrypted_message).digest()
        if recipient_id not in self._message_queue:
            self._message_queue[recipient_id] = {}
        self._message_queue[recipient_id][message_id] = (sender_id, encrypted_message)

        # Send the encrypted_message to the recipient.
        if recipient_id in self._node_ips:
            recipient_addr = self._node_ips[recipient_id]
            self._send_command(ConnectionProtocol.SEND_MESSAGE, recipient_addr, message_id + sender_id + encrypted_message)

    def _handle_create_a_group_chat(self, addr: IPv6Address, data: bytes) -> None:
        # Determine the next available multicast address for a group.
        next_available_suffix = len(self._groups_multicast_addresses)
        multicast_address = f"ff02::1:{next_available_suffix}"
        group_id = data[:DIGEST_SIZE]

        # Store the group's multicast address and the node's IP.
        self._groups_multicast_addresses[group_id] = IPv6Address(multicast_address)
        self._node_ips[group_id] = IPv6Address(multicast_address)
        print(f"Registered group {group_id}" + f" with address {multicast_address}.")

        # Send the ACK to the client.
        sending_data = group_id + self._groups_multicast_addresses[group_id].packed
        self._send_command(ConnectionProtocol.CREATE_GC_ACK, addr, sending_data)

    def _handle_message_ack(self, addr: IPv6Address, data: bytes) -> None:
        # Split the data into the sender's username and the message_id.
        sender_username = [k for k, v in self._node_ips.items() if v == addr][0]
        message_id = data

        # Remove the message from the queue.
        self._message_queue[sender_username].pop(message_id)
