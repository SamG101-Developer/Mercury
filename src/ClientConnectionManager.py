import json
import socket, subprocess, time, os
from base64 import b64encode
from dataclasses import dataclass
from ipaddress import IPv6Address
from threading import Thread

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

from src.ConnectionManager import ConnectionManager
from src.ConnectionProtocol import ConnectionProtocol
from src.Crypto import *


SERVER_IP = IPv6Address("fe80::399:3723:1f1:ea97")


@dataclass(kw_only=True)
class ChatInfo:
    shared_secret: bytes


class ClientConnectionManager(ConnectionManager):
    _server_ready: bool
    _cert = None
    _chat_info: dict[bytes, ChatInfo]  # ID -> (Shared secret, Public key, Ready)
    _kex_pub_keys: dict[bytes, bytes]  # ID -> Public Key
    _username: bytes
    _secret_key: rsa.RSAPrivateKey
    _public_key: rsa.RSAPublicKey
    _chats: dict[bytes, list[bytes]]  # ID -> [Raw Message]

    def __init__(self):
        super().__init__()
        self._server_ready = False
        self._username = b""
        self._chat_info = {}
        self._kex_pub_keys = {}

        self._load_chat_info()
        self._boot_sequence()
        Thread(target=self._setup_local_messaging_reader_port).start()

        while True:
            command = input("Cmd > ")
            self._handle_local_command(command)

    def _load_chat_info(self) -> None:
        # Get the known keys and check if the recipient is already in a chat.
        chats = json.load(open("src/_chat_keys/keys.json", "r"))
        for key in chats.keys():
            self._chat_info[key] = ChatInfo(shared_secret=chats[key]["shared_secret"])

    def _boot_sequence(self):
        self.register_to_server()
        while not self._cert:
            pass
        self.tell_server_client_is_online()

    def _setup_local_messaging_reader_port(self):
        reader_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        reader_socket.bind(('::1', 20002))

        while True:
            message, addr = reader_socket.recvfrom(1024)
            print(f"Received message from {addr}: {message}")
            if addr[0] != "::1": continue
            encoded_recipient_id, message = message[:DIGEST_SIZE], message[DIGEST_SIZE:]
            self._send_message_to(message, encoded_recipient_id)

    def register_to_server(self) -> None:
        # Don't allow double registration.
        if os.path.exists("src/_my_keys"):
            self._secret_key = load_pem_private_key(open("src/_my_keys/private_key.pem", "rb").read(), password=None)
            self._public_key = load_pem_public_key(open("src/_my_keys/public_key.pem", "rb").read())
            self._username = open("src/_my_keys/identifier.txt", "rb").read()
            self._cert = open("src/_my_keys/certificate.pem", "rb").read()
            self._handle_error(IPv6Address("::1"), b"Already registered.")
            return

        os.mkdir("src/_my_keys")
        self.register_to_server_internal(input("Username: "))

    def register_to_server_internal(self, username: str) -> None:
        # Create a username (hash = ID), and generate a key pair.
        hashed_username = HASH_ALGORITHM(username.encode()).digest()
        self._username = hashed_username
        self._secret_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._secret_key.public_key()
        print("Generated asymmetric RSA key pair")

        # Save the key pair to disk.
        secret_pem = self._secret_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        public_pem = self._public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.PKCS1)
        open("src/_my_keys/private_key.pem", "wb").write(secret_pem)
        open("src/_my_keys/public_key.pem", "wb").write(public_pem)
        open("src/_my_keys/identifier.txt", "wb").write(hashed_username)
        print("\tRegistering with the server...")

        # Send the registration command to the server.
        self._send_command(ConnectionProtocol.REGISTER, SERVER_IP, hashed_username + public_pem, to_server=True)

    def tell_server_client_is_online(self) -> None:
        print("Notifying server that client is online.")

        # Tell the client that the node with this username is now online.
        challenge_raw = str(time.time()).zfill(TIME_LENGTH).encode()
        challenge_sig = self._secret_key.sign(
            data=challenge_raw,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            algorithm=hashes.SHA256())
        challenge = challenge_sig + challenge_raw

        sending_data = self._cert + challenge
        self._send_command(ConnectionProtocol.CLIENT_ONLINE, SERVER_IP, sending_data, to_server=True)

        # Wait for the server to be ready.
        while not self._server_ready:
            pass

    def _send_message_to(self, message: bytes, recipient_id: bytes) -> None:
        print(f"Sending message {message} to recipient {recipient_id}.")

        # Get the recipient's shared secret and public key.
        chat = self._chat_info[recipient_id]

        # Encrypt the message and send it.
        encrypted_message = self._encrypt_message(chat.shared_secret, message)
        self._send_command(ConnectionProtocol.SEND_MESSAGE, SERVER_IP, self._username + recipient_id + encrypted_message, to_server=True)

    def _handle_local_command(self, command: str) -> None:
        if not " " in command:
            self._handle_error(IPv6Address("::1"), b"Invalid local command.")

        command, data = command.split(" ", 1)

        match command:
            # When the user wants to message someone
            case "chat":
                Thread(target=self._open_chat_with, args=(data, )).start()

    def _handle_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes) -> None:
        match command:
            # When the server confirms the registration and sends the client a certificate.
            case ConnectionProtocol.REGISTER_ACK_AND_CERT:
                self._handle_register_ack_and_cert(data)

            # When the server confirms that the client is online (ready to receive from it).
            case ConnectionProtocol.CLIENT_ONLINE_ACK:
                self._handle_client_online_ack()

            # When the server tells the client that another node is accepting the chat request.
            case ConnectionProtocol.INVITE_ACK:
                self._handle_invite_ack(addr, data)

            # When the server sends a message from a node to the client.
            case ConnectionProtocol.SEND_MESSAGE:
                self._handle_received_message(addr, data)

            # When the server confirms the creation of a group chat.
            case ConnectionProtocol.CREATE_GC_ACK:
                ...

            # When the server tells the client to prepare for a solo chat.
            case ConnectionProtocol.PREP_FOR_SOLO:
                self._prepare_for_solo_chat(addr, data)

            # When the server tells the client to prepare for a group chat.
            case ConnectionProtocol.PREP_FOR_GC:
                ...

            # When the server invites the client to a group chat (from another node).
            case ConnectionProtocol.GC_INVITE:
                ...

            # When the server sends a group message to the client.
            case ConnectionProtocol.SEND_GROUP_MESSAGE:
                ...

            # When a node is online (told so by server, + their public key)
            case ConnectionProtocol.NODE_IS_ONLINE:
                self._handle_node_online(addr, data)

            case ConnectionProtocol.ERROR:
                self._handle_error(addr, data)

    def _handle_register_ack_and_cert(self, data: bytes) -> None:
        # Extract the certificate from the data.
        certificate_sig = data[:RSA_SIGNATURE_SIZE]
        certificate_raw = data[RSA_SIGNATURE_SIZE:]

        # Load the server's public key and verify the certificate.
        server_public_key = open("src/_server_keys/public_key.pem", "rb").read()
        server_public_key = load_pem_public_key(server_public_key)

        # If the certificate is valid, store it and set the server as ready.
        try:
            server_public_key.verify(
                signature=certificate_sig,
                data=certificate_raw,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())

            self._cert = data
            open("src/_my_keys/certificate.pem", "wb").write(data)
            print("Certificate verified.")

        except InvalidSignature:
            print("Certificate verification failed.")
            self._cert = None

    def _handle_client_online_ack(self) -> None:
        # Mark the server as ready.
        self._server_ready = True
        print("Server ready for communication.")

    def _prepare_for_solo_chat(self, addr: IPv6Address, data: bytes) -> None:
        # Get the chat initiator's username and public key.
        chat_initiator_username = data[:DIGEST_SIZE]
        chat_initiator_public_key = data[DIGEST_SIZE:-IP_SIZE]
        chat_initiator_ip_address = IPv6Address(data[-IP_SIZE:])

        # Create a shared secret, KEM it and sign it.
        shared_secret = os.urandom(32)
        kem_wrapped_shared_secret = load_pem_public_key(chat_initiator_public_key).encrypt(
            plaintext=shared_secret,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))

        signed_kem_wrapped_shared_secret = self._secret_key.sign(
            data=kem_wrapped_shared_secret,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            algorithm=hashes.SHA256())

        # Send the signed KEM to the chat initiator.
        self._chat_info[chat_initiator_username] = ChatInfo(shared_secret=shared_secret)

        sending_data = self._username + self._cert + kem_wrapped_shared_secret + signed_kem_wrapped_shared_secret
        self._send_command(ConnectionProtocol.INVITE_ACK, chat_initiator_ip_address, sending_data)

    def _handle_invite_ack(self, addr: IPv6Address, data: bytes) -> None:
        # Load the chat username into the dictionary, with an empty key (no KEX yet)
        chat_receiver_id                 = data[:(pre := DIGEST_SIZE)]
        chat_receiver_certificate_sig    = data[pre:(pre := pre + RSA_SIGNATURE_SIZE)]
        chat_receiver_certificate_raw    = data[pre:(pre := pre + RSA_CERTIFICATE_SIZE)]
        kem_wrapped_shared_secret        = data[pre:(pre := pre + RSA_KEM_SIZE)]
        signed_kem_wrapped_shared_secret = data[pre:]

        # Verify the recipient's certificate is valid.
        try:
            server_public_key_raw = open("src/_server_keys/public_key.pem", "rb").read()
            load_pem_public_key(server_public_key_raw).verify(
                signature=chat_receiver_certificate_sig,
                data=chat_receiver_certificate_raw,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())

        except InvalidSignature:
            print("Invalid certificate.")
            return

        # Wait for the public key (should have already been received at this point)
        while chat_receiver_id not in self._kex_pub_keys.keys():
            pass
        chat_receiver_public_key_raw = self._kex_pub_keys[chat_receiver_id]
        del self._kex_pub_keys[chat_receiver_id]

        # Verify the signed KEM is valid.
        try:
            load_pem_public_key(chat_receiver_public_key_raw).verify(
                signature=signed_kem_wrapped_shared_secret,
                data=kem_wrapped_shared_secret,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())
        except InvalidSignature:
            print("Invalid KEM signature.")
            return

        # Decrypt the KEM and store the shared secret.
        shared_secret = self._secret_key.decrypt(
            ciphertext=kem_wrapped_shared_secret,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))

        current_stored_keys = json.load(open("src/_chat_keys/keys.json", "r"))
        current_stored_keys[chat_receiver_id] = {"shared_secret": shared_secret}
        json.dump(current_stored_keys, open("src/_chat_keys/keys.json", "w"))

        self._chat_info[chat_receiver_id] = ChatInfo(shared_secret=shared_secret)

    def _handle_received_message(self, addr: IPv6Address, data: bytes) -> None:
        # Extract the message ID, recipient ID, and encrypted message.
        message_id = data[:DIGEST_SIZE]
        recipient_id = data[DIGEST_SIZE:DIGEST_SIZE * 2]
        encrypted_message = data[DIGEST_SIZE * 2:]

        # Decrypt the message and store it.
        shared_secret = self._chat_info[recipient_id].shared_secret
        message = self._decrypt_message(shared_secret, encrypted_message)
        self._chats[recipient_id].append(message)

        # ACK the message.
        self._send_command(ConnectionProtocol.MESSAGE_ACK, SERVER_IP, message_id, to_server=True)

        # Put the message in the chat window if there is one.
        # todo

    def _handle_node_online(self, addr: IPv6Address, data: bytes) -> None:
        # Verify the node's certificate and extract the public key.
        certificate_sig = data[:RSA_SIGNATURE_SIZE]
        certificate_raw = data[RSA_SIGNATURE_SIZE:]

        try:
            server_public_key = open("src/_server_keys/public_key.pem", "rb").read()
            load_pem_public_key(server_public_key).verify(
                signature=certificate_sig,
                data=certificate_raw,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())
        except InvalidSignature:
            print("Invalid certificate.")
            return

        recipient_id = certificate_raw[:DIGEST_SIZE]
        recipient_public_key = certificate_raw[-RSA_PUBLIC_KEY_PEM_SIZE:]

        self._kex_pub_keys[recipient_id] = recipient_public_key

    def _open_chat_with(self, data: str) -> None:
        # Get the recipient id.
        recipient_id = HASH_ALGORITHM(data.encode()).digest()

        # If the recipient is not known, invite them to chat.
        if recipient_id not in self._chat_info.keys():
            self._send_command(ConnectionProtocol.SOLO_INVITE, SERVER_IP, recipient_id, to_server=True)

        # Create the message window (as a command line window), and save the process.
        port = str(20003 + len(self._chat_info))
        encoded_recipient_id = b64encode(recipient_id).decode()
        args = f"python src/ClientMessagingShell.py {port} {encoded_recipient_id}"
        args = f"lxterminal -e {args}" if os.name == "posix" else f"cmd /c start {args}"
        subprocess.call(args=[args], shell=True)

    def _handle_error(self, address: IPv6Address, data: bytes) -> None:
        print(f"Error from {address}: {data}")

    def _encrypt_message(self, shared_secret: bytes, message: bytes) -> bytes:
        # Use AES GCM to encrypt the message.
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag

        return iv + tag + ciphertext

    def _decrypt_message(self, shared_secret: bytes, encrypted_message: bytes) -> bytes:
        # Use AES GCM to decrypt the message.
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        message = decryptor.update(ciphertext) + decryptor.finalize()

        return message