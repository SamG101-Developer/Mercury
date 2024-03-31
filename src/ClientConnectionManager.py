import os
import time
from ipaddress import IPv6Address

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


class ClientConnectionManager(ConnectionManager):
    _server_ready: bool
    _cert = None
    _chat_info: dict[bytes, tuple[bytes, bytes, bool]]  # ID -> (Shared secret, Public key, Ready)
    _username: bytes
    _secret_key: rsa.RSAPrivateKey
    _public_key: rsa.RSAPublicKey
    _chats: dict[bytes, list[bytes]]  # ID -> [Raw Message]

    def __init__(self):
        super().__init__()
        self._server_ready = False
        self._username = b""
        self.register_to_server()
        while not self._cert:
            pass
        self.tell_server_client_is_online()

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

        # Create a username (hash = ID), and generate a key pair.
        username = input("Username: ")
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
        self._send_command(ConnectionProtocol.REGISTER, SERVER_IP, hashed_username + public_pem)

    def tell_server_client_is_online(self) -> None:
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
        print(sending_data)
        self._send_command(ConnectionProtocol.CLIENT_ONLINE, SERVER_IP, sending_data)

        # Wait for the server to be ready.
        while not self._server_ready:
            pass

    def send_message_to(self, message: bytes, recipient_id: bytes) -> None:
        # Get the recipient's shared secret and public key.
        shared_secret, public_key, ready = self._chat_info[recipient_id]

        # If the recipient is not ready, wait for them to be.
        if not ready:
            self._handle_error(IPv6Address("::1"), b"Recipient not ready.")
            return

        # Encrypt the message and send it.
        encrypted_message = self._encrypt_message(shared_secret, message)
        self._send_command(ConnectionProtocol.SEND_MESSAGE, SERVER_IP, self._username + recipient_id + encrypted_message)

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

    def _prepare_for_solo_chat(self, addr: IPv6Address, data: bytes) -> None:
        # Get the chat initiator's username and public key.
        chat_initiator_username = data[:DIGEST_SIZE]
        chat_initiator_public_key = data[DIGEST_SIZE:-4]
        chat_initiator_ip_address = IPv6Address(data[-4:])

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
        self._chat_info[chat_initiator_username] = (shared_secret, chat_initiator_public_key, True)
        self._send_command(ConnectionProtocol.INVITE_ACK, chat_initiator_ip_address, self._username + self._cert + kem_wrapped_shared_secret + signed_kem_wrapped_shared_secret)

    def _handle_invite_ack(self, addr: IPv6Address, data: bytes) -> None:
        # Load the chat username into the dictionary, with an empty key (no KEX yet)
        chat_receiver_id = data[:DIGEST_SIZE]
        chat_receiver_certificate = data[DIGEST_SIZE:DIGEST_SIZE + RSA_CERTIFICATE_SIZE]
        kem_wrapped_shared_secret = data[DIGEST_SIZE + RSA_CERTIFICATE_SIZE:DIGEST_SIZE + RSA_CERTIFICATE_SIZE + RSA_KEM_SIZE]
        signed_kem_wrapped_shared_secret = data[-RSA_SIGNATURE_SIZE:]

        # Verify the recipient's certificate is valid.
        try:
            server_public_key_raw = open("_server_keys/public_key.pem", "rb").read()
            server_public_key: rsa.RSAPublicKey = load_pem_public_key(server_public_key_raw)
            server_public_key.verify(
                signature=chat_receiver_certificate,
                data=self._cert,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())

        except InvalidSignature:
            print("Invalid certificate.")
            return

        # Verify the signed KEM is valid.
        chat_receiver_public_key = self._chat_info[chat_receiver_id][1]
        load_pem_public_key(chat_receiver_public_key).verify(
            signature=signed_kem_wrapped_shared_secret,
            data=kem_wrapped_shared_secret,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            algorithm=hashes.SHA256())

        # Decrypt the KEM and store the shared secret.
        shared_secret = self._secret_key.decrypt(
            ciphertext=kem_wrapped_shared_secret,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))

        self._chat_info[chat_receiver_id] = (shared_secret, chat_receiver_public_key, True)

    def _handle_received_message(self, addr: IPv6Address, data: bytes) -> None:
        # Extract the message ID, sender, and encrypted message.
        message_id = data[:DIGEST_SIZE]
        sender = data[DIGEST_SIZE:DIGEST_SIZE * 2]
        encrypted_message = data[DIGEST_SIZE * 2:]

        # Decrypt the message and store it.
        shared_secret = self._chat_info[message_id][0]
        message = self._decrypt_message(shared_secret, encrypted_message)
        self._chats[message_id].append(sender + message)

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