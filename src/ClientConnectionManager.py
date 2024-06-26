import json
import shutil
import socket, struct, subprocess, time, os, tkinter as tk
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
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
from src.Message import Message
from src.Crypto import *

from tkinter import filedialog


SERVER_IP = IPv6Address("fe80::7c7b:e49b:8cd:dc22")


@dataclass(kw_only=True)
class ChatInfo:
    shared_secret: bytes
    local_port: int = field(default=-1)


class ClientConnectionManager(ConnectionManager):
    _server_ready: bool
    _cert = None
    _chat_info: dict[bytes, ChatInfo]  # ID -> ChatInfo
    _node_certs: dict[bytes, bytes]  # ID -> Certificate
    _group_chat_multicast_addresses: dict[bytes, IPv6Address]  # GroupID -> Multicast IP
    _temp_node_ip_addresses: dict[bytes, IPv6Address]  # ID -> IP
    _my_username: str
    _my_id: bytes
    _secret_key: rsa.RSAPrivateKey
    _public_key: rsa.RSAPublicKey
    _chats: dict[bytes, list[Message]]  # ID -> [Raw Message]

    def __init__(self):
        super().__init__()

        # Initialize attributes
        self._server_ready = False
        self._my_id = b""
        self._chat_info = {}
        self._chats = {}
        self._node_certs = {}
        self._group_chat_multicast_addresses = {}
        self._temp_node_ip_addresses = {}

        # Load any pre-known chat keys, and initiate the boot sequence.
        self._load_chat_info()
        self._boot_sequence()

        # Setup the local socket for extra shells to message with.
        Thread(target=self._setup_local_messaging_reader_port).start()

        # Listen to commands from the client user input.
        while True:
            command = input("Cmd > ")
            self._handle_local_command(command)

    def _load_chat_info(self) -> None:
        # If the colder is missing, create it.
        if not os.path.exists("src/_chat_keys"):
            print("No chat keys directory found. Creating one.")
            os.mkdir("src/_chat_keys")

        # If the file is missing, create it.
        if not os.path.exists("src/_chat_keys/keys.json"):
            print("No chat keys file found. Creating one.")
            open("src/_chat_keys/keys.json", "w").write("{}")

        # If the store folder is missing, create it
        if not os.path.exists("src/_store"):
            print("No store folder found. Creating one.")
            os.mkdir("src/_store")

        # Load known keys and initialize a chat list of messages.
        chats = json.load(open("src/_chat_keys/keys.json", "r"))
        for recipient_id in chats.keys():
            self._chat_info[b64decode(recipient_id)] = ChatInfo(shared_secret=b64decode(chats[recipient_id]["shared_secret"]))
            self._chats[b64decode(recipient_id)] = []  # todo: load saved messages here

    def _boot_sequence(self):
        # Register this node with the server (only happens for a new user). Wait for the certificate.
        self.register_to_server()
        while not self._cert: pass

        # Notify the server that the client is online.
        self.tell_server_client_is_online()

    def _setup_local_messaging_reader_port(self):
        # The reader socket will receive messages from the client messaging shell (what the user types, to send to other
        # nodes)
        reader_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        reader_socket.bind(('::1', 20002))

        # Continuously receive messages from the client messaging shell and call the handler function.
        while True:
            # Receive the message and check it is from the local machine.
            message, addr = reader_socket.recvfrom(1024)
            if addr[0] != "::1": continue
            encoded_recipient_id, message = message[:DIGEST_SIZE], message[DIGEST_SIZE:]

            # Check if the message is from a group chat, or a solo chat.
            port_from = addr[1]
            group_id = next((who for who, info in self._chat_info.items() if info.local_port == port_from and who in self._group_chat_multicast_addresses.keys()), b"")

            # Check if the message needs to contain rich media (image, voice)
            if message == b"[rm-file]":
                root = tk.Tk()
                root.withdraw()
                file_path = filedialog.askopenfilename()
                file_name = os.path.split(file_path)[1]
                root.destroy()
                message = b"[rm-file:" + file_name.encode() + b":" + open(file_path, "rb").read() + b"]"

            # Send the message
            self._send_message_to(message, encoded_recipient_id, for_group=group_id)

        reader_socket.close()

    def register_to_server(self) -> None:
        # Don't allow double registration.
        if os.path.exists("src/_my_keys"):
            try:
                self._secret_key = load_pem_private_key(open("src/_my_keys/private_key.pem", "rb").read(), password=None)
                self._public_key = load_pem_public_key(open("src/_my_keys/public_key.pem", "rb").read())
                self._my_username = open("src/_my_keys/username.txt", "r").read()
                self._my_id = open("src/_my_keys/identifier.txt", "rb").read()
                self._cert = open("src/_my_keys/certificate.pem", "rb").read()
            except FileNotFoundError:
                self._reset_node_info()
                return
            self._handle_error(IPv6Address("::1"), f"Logged in as {self._my_username}.".encode())
            return

        self.register_to_server_internal(input("Username: "))

    def register_to_server_internal(self, username: str) -> None:
        # Create a username (hash = ID), and generate a key pair.
        hashed_username = HASH_ALGORITHM(username.encode()).digest()
        self._my_username = username
        self._my_id = hashed_username
        self._secret_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._secret_key.public_key()
        print("Generated asymmetric RSA key pair")

        # Save the key pair to disk.
        secret_pem = self._secret_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        public_pem = self._public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.PKCS1)
        os.mkdir("src/_my_keys")
        open("src/_my_keys/private_key.pem", "wb").write(secret_pem)
        open("src/_my_keys/public_key.pem", "wb").write(public_pem)
        open("src/_my_keys/username.txt", "w").write(username)
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

    def _send_message_to(self, message: bytes, recipient_id: bytes, for_group: bytes = b"") -> None:
        # Get the recipient's shared secret and public key.
        chat = self._chat_info[recipient_id]

        # Encrypt the message.
        message += b"\n"
        self._chats[recipient_id].append(Message(message_bytes=b"Me > " + message, am_i_sender=True))
        encrypted_message = self._encrypt_message(chat.shared_secret, self._my_username.encode() + b" > " + message)

        # Send the message to the server.
        if not for_group:
            sending_data = recipient_id + encrypted_message
            self._send_command(ConnectionProtocol.SEND_MESSAGE, SERVER_IP, sending_data, to_server=True)
        else:
            sending_data = for_group + recipient_id + encrypted_message
            self._send_command(ConnectionProtocol.GC_SEND_MESSAGE, SERVER_IP, sending_data, to_server=True)

    def _handle_local_command(self, command: str) -> None:
        if " " not in command:
            self._handle_error(IPv6Address("::1"), b"Invalid local command.")

        command, data = command.split(" ", 1)

        match command:
            # When the user wants to message someone
            case "chat":
                Thread(target=self._open_chat_with, args=(data, )).start()

            # When the user wants to create a group chat
            case "makegroup":
                Thread(target=self._make_group_chat, args=(data, )).start()

            # When the user wants to invite someone to a group chat
            case "invitetogroup":
                Thread(target=self._invite_to_group_chat, args=(data, )).start()

            # Reset information
            case "reset":
                Thread(target=self._reset_node_info).start()

    def _handle_command(self, command: ConnectionProtocol, addr: IPv6Address, data: bytes) -> None:
        match command:
            # When the server confirms the registration and sends the client a certificate.
            case ConnectionProtocol.REGISTER_ACK_AND_CERT:
                self._handle_register_ack_and_cert(data)

            # When the server confirms that the client is online (ready to receive from it).
            case ConnectionProtocol.CLIENT_ONLINE_ACK:
                self._handle_client_online_ack()

            # When the server tells the client that another node is accepting the chat request.
            case ConnectionProtocol.SOLO_INVITE:
                self._handle_solo_invite(addr, data)

            # When the server sends a message from a node to the client.
            case ConnectionProtocol.SEND_MESSAGE:
                self._handle_received_message(addr, data)

            # When the server confirms the creation of a group chat.
            case ConnectionProtocol.CREATE_GC_ACK:
                self._handle_group_chat_creation_ack(addr, data)

            # When the server invites the client to a group chat (from another node).
            case ConnectionProtocol.GC_INVITE:
                self._handle_group_chat_invite(addr, data)

            # When a node is online (told so by server, + their public key)
            case ConnectionProtocol.NODE_INFO:
                self._handle_node_online(addr, data)

            # When a list of IPs are sent to invite members to a group chat
            case ConnectionProtocol.GC_NODE_INFO:
                self._handle_gc_node_info(addr, data)

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

    def _handle_group_chat_creation_ack(self, addr: IPv6Address, data: bytes) -> None:
        # Extract the group id from the data.
        group_id = data[:DIGEST_SIZE]
        multicast_address = IPv6Address(data[DIGEST_SIZE:])

        # Store the group id and create an empty chat list. Create a shared secret for the group chat.
        self._chat_info[group_id] = ChatInfo(shared_secret=os.urandom(32))
        self._chats[group_id] = []
        self._group_chat_multicast_addresses[group_id] = multicast_address
        print("Server acknowledges group chat")

        # Connect the socket to the multicast receiver.
        self._attach_to_multicast_group(multicast_address)

    def _attach_to_multicast_group(self, multicast_address: IPv6Address) -> None:
        # Attach the receiver socket to a specific multicast group.
        socket_multicast_group = socket.inet_pton(socket.AF_INET6, multicast_address.exploded)
        multicast_request = socket_multicast_group + struct.pack("@I", 0)
        self._server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, multicast_request)

    def _handle_group_chat_invite(self, addr: IPv6Address, data: bytes) -> None:
        print(f"Invite received for {data[IP_SIZE:IP_SIZE + DIGEST_SIZE]}.")

        # Extract the multicast address and group id from the data.
        multicast_address = IPv6Address(data[:IP_SIZE])
        group_id = data[IP_SIZE:IP_SIZE + DIGEST_SIZE]
        self._chat_info[group_id] = ChatInfo(shared_secret=b"")  # Shared secret loaded later.
        self._chats[group_id] = []

        # Use the solo invite handler to process the group invite (store keys etc.).
        self._handle_solo_invite(addr, data[IP_SIZE:])

        # Connect the socket to the multicast receiver.
        self._group_chat_multicast_addresses[group_id] = multicast_address
        self._attach_to_multicast_group(multicast_address)

    def _handle_solo_invite(self, addr: IPv6Address, data: bytes) -> None:
        # Load the chat username into the dictionary, with an empty key (no KEX yet)
        chat_initiator_id                = data[:(pre := DIGEST_SIZE)]
        chat_initiator_certificate_sig   = data[pre:(pre := pre + RSA_SIGNATURE_SIZE)]
        chat_initiator_certificate_raw   = data[pre:(pre := pre + RSA_CERTIFICATE_SIZE)]
        kem_wrapped_shared_secret        = data[pre:(pre := pre + RSA_KEM_SIZE)]
        signed_kem_wrapped_shared_secret = data[pre:]

        # Verify the recipient's certificate is valid.
        try:
            server_public_key_raw = open("src/_server_keys/public_key.pem", "rb").read()
            load_pem_public_key(server_public_key_raw).verify(
                signature=chat_initiator_certificate_sig,
                data=chat_initiator_certificate_raw,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())

        except InvalidSignature:
            print("Invalid certificate.")
            return

        # Verify the signed KEM is valid.
        chat_initiator_public_key = chat_initiator_certificate_raw[DIGEST_SIZE:]
        try:
            load_pem_public_key(chat_initiator_public_key).verify(
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

        # Store the shared secret.
        current_stored_keys = json.load(open("src/_chat_keys/keys.json", "r"))
        current_stored_keys[b64encode(chat_initiator_id).decode()] = {"shared_secret": b64encode(shared_secret).decode()}
        json.dump(current_stored_keys, open("src/_chat_keys/keys.json", "w"))

        # Load the shared secret into the chat info and create an empty chat list.
        self._chat_info[chat_initiator_id] = ChatInfo(shared_secret=shared_secret)
        self._chats[chat_initiator_id] = []

    def _handle_received_message(self, addr: IPv6Address, data: bytes) -> None:
        # Extract the message ID, recipient ID, and encrypted message.
        message_id = data[:DIGEST_SIZE]
        sender_id = data[DIGEST_SIZE:DIGEST_SIZE * 2]
        encrypted_message = data[DIGEST_SIZE * 2:]

        # Wait for the sender to be in the chat info (could still be processing KEM)
        while sender_id not in self._chat_info.keys():
            pass

        # Decrypt the message and store it.
        shared_secret = self._chat_info[sender_id].shared_secret
        message = self._decrypt_message(shared_secret, encrypted_message)
        self._chats[sender_id].append(Message(message_bytes=message, am_i_sender=False))

        # ACK the message (not for group chats).
        if sender_id not in self._group_chat_multicast_addresses.keys():
            self._send_command(ConnectionProtocol.MESSAGE_ACK, SERVER_IP, message_id, to_server=True)

        # Put the message in the chat window if there is a process for the chat window, and it is alive.
        local_port = self._chat_info[sender_id].local_port

        if local_port != -1:
            # Handle rich media downloads
            if message[message.find(b"> ") + 2:].startswith(b"[rm-file:"):
                _, file_name, file_contents = message.split(b":", 2)
                open(f"src/_store/{file_name.decode()}", "wb").write(file_contents)
                message = message[:message.find(b"> ")] + f"Received file {file_name.decode()}\n".encode()

            self._push_message_into_messaging_window(sender_id, local_port, message)

    def _push_message_into_messaging_window(self, sender_id: bytes, local_port: int, message: bytes) -> None:
        sending_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sending_socket.sendto(message, ("::1", local_port))

    def _handle_node_online(self, addr: IPv6Address, data: bytes) -> None:
        # Verify the node's certificate and extract the public key.
        certificate_sig = data[:RSA_SIGNATURE_SIZE]
        certificate_raw = data[RSA_SIGNATURE_SIZE:-IP_SIZE]

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
            print("Invalid certificate when retrieving node information.")
            return

        # Extract the id, public key and ip of the recipient.
        recipient_id = certificate_raw[:DIGEST_SIZE]
        recipient_public_key = certificate_raw[DIGEST_SIZE:DIGEST_SIZE + RSA_PUBLIC_KEY_PEM_SIZE]
        recipient_ip_address = IPv6Address(data[-IP_SIZE:])

        # Generate a shared secret, KEM it and sign the KEM.
        shared_secret = os.urandom(32)
        kem_wrapped_shared_secret = load_pem_public_key(recipient_public_key).encrypt(
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

        # Store the shared secret.
        current_stored_keys = json.load(open("src/_chat_keys/keys.json", "r"))
        current_stored_keys[b64encode(recipient_id).decode()] = {"shared_secret": b64encode(shared_secret).decode()}
        json.dump(current_stored_keys, open("src/_chat_keys/keys.json", "w"))

        # Load the shared secret into the chat info and create an empty chat list.
        self._chat_info[recipient_id] = ChatInfo(shared_secret=shared_secret)
        self._chats[recipient_id] = []
        self._node_certs[recipient_id] = certificate_raw

        # Send the signed KEM to the chat recipient.
        sending_data = self._my_id + self._cert + kem_wrapped_shared_secret + signed_kem_wrapped_shared_secret
        self._send_command(ConnectionProtocol.SOLO_INVITE, recipient_ip_address, sending_data)

    def _handle_gc_node_info(self, addr: IPv6Address, data: bytes) -> None:
        # todo: needs auth from server

        # Extract the recipient id, ip and certificate.
        recipient_id = data[:DIGEST_SIZE]
        recipient_ip = IPv6Address(data[DIGEST_SIZE:DIGEST_SIZE + IP_SIZE])
        recipient_cert = data[DIGEST_SIZE + IP_SIZE:]

        # Store the recipient's IP and certificate.
        self._node_certs[recipient_id] = recipient_cert
        self._temp_node_ip_addresses[recipient_id] = recipient_ip

    def _open_chat_with(self, data: str) -> None:
        # Get the recipient id.
        recipient_id = HASH_ALGORITHM(data.encode()).digest()

        # If the recipient is not known, invite them to chat.
        if recipient_id not in self._chat_info.keys():
            self._send_command(ConnectionProtocol.GET_NODE_INFO, SERVER_IP, recipient_id, to_server=True)
        while recipient_id not in self._chat_info.keys():
            pass

        # Create the message window (as a command line window), and save the process. Allow port re-use.
        # if (port := self._chat_info[recipient_id].local_port) == -1:
        port = str(20003 + list(self._chat_info.keys()).index(recipient_id))
        self._chat_info[recipient_id].local_port = int(port)

        encoded_recipient_id = b64encode(recipient_id).decode()
        args = f"python src/ClientMessagingShell.py {port} {encoded_recipient_id}"
        args = f"lxterminal -e {args}" if os.name == "posix" else f"cmd /c start {args}"
        proc = subprocess.Popen(args=[args], shell=True)

        time.sleep(2)  # todo : change

        # If there is a queue of messages for the recipient, send them into the chat.
        for message in self._chats[recipient_id].copy():
            self._push_message_into_messaging_window(recipient_id, int(port), message.message_bytes)

    def _make_group_chat(self, data: str) -> None:
        # Get the group ID, and send it to the server.
        group_id = HASH_ALGORITHM(data.encode()).digest()
        self._send_command(ConnectionProtocol.CREATE_GC, SERVER_IP, group_id, to_server=True)

    def _invite_to_group_chat(self, data: str) -> None:
        # Get the group ID and recipient IDs to add to the group chat.
        group_name, *recipient_usernames = data.split(" ")
        group_id = HASH_ALGORITHM(group_name.encode()).digest()
        recipient_ids = [HASH_ALGORITHM(username.encode()).digest() for username in recipient_usernames]
        print(f"Inviting {recipient_usernames} to group chat {group_name}.")

        # Wait for the group chat to be created (only relevant if the invite is right after group creation).
        while group_id not in self._chat_info.keys():
            pass

        # Load the shared secret into the chat info and create an empty chat list.
        group_shared_secret = self._chat_info[group_id].shared_secret

        # Load the IPs of the recipients for their invites.
        for recipient_id in recipient_ids:
            self._send_command(ConnectionProtocol.GC_GET_NODE_INFO, SERVER_IP, recipient_id, to_server=True)

        # Store the shared secret.
        current_stored_keys = json.load(open("src/_chat_keys/keys.json", "r"))
        current_stored_keys[b64encode(group_id).decode()] = {"shared_secret": b64encode(group_shared_secret).decode()}
        json.dump(current_stored_keys, open("src/_chat_keys/keys.json", "w"))

        multicast_address = self._group_chat_multicast_addresses[group_id].packed

        for recipient_id in recipient_ids:
            # Wait for the recipient to be in the ip address map.
            while recipient_id not in self._temp_node_ip_addresses.keys():
                pass

            recipient_public_key = self._node_certs[recipient_id][RSA_SIGNATURE_SIZE + DIGEST_SIZE:]
            recipient_ip_address = self._temp_node_ip_addresses[recipient_id]
            del self._temp_node_ip_addresses[recipient_id]

            kem_wrapped_shared_secret = load_pem_public_key(recipient_public_key).encrypt(
                plaintext=group_shared_secret,
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

            # Send the signed KEM to the chat recipient, as a group invite.
            sending_data = multicast_address + group_id + self._cert + kem_wrapped_shared_secret + signed_kem_wrapped_shared_secret
            self._send_command(ConnectionProtocol.GC_INVITE, recipient_ip_address, sending_data)
            print(f"Invited {recipient_id} to group chat {group_name}.")

    def _reset_node_info(self) -> None:
        # Clear key files and any identifying information, and re-register
        shutil.rmtree("src/_my_keys")
        shutil.rmtree("src/_chat_keys")
        self.register_to_server()

    def _handle_error(self, address: IPv6Address, data: bytes) -> None:
        print(f"Error from {address}: {data}")

    def _encrypt_message(self, shared_secret: bytes, message: bytes) -> bytes:
        # Create an IV and register the cipher.
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(iv))
        encryptor = cipher.encryptor()

        # Encrypt the message and return the IV, tag and ciphertext.
        ciphertext = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag
        return iv + tag + ciphertext

    def _decrypt_message(self, shared_secret: bytes, encrypted_message: bytes) -> bytes:
        # Extract the IV, tag and ciphertext from the encrypted message.
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]

        # Register the cipher and decrypt the message.
        cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        message = decryptor.update(ciphertext) + decryptor.finalize()
        return message
