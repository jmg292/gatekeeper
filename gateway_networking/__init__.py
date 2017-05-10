import json
import asyncio
import gateway_security


class ClientStateObject:

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.is_authorized = False
        self.rsa_key_digest = None
        self.assigned_nonce = None
        self.inbound_message = None
        self.outbound_message = None
        self.handshake_finished = False
        self.ephemeral_key_object = None
        self.cryptographic_interface = None


class HandshakeInterface:

    def __init__(self, rsa_private_key, configuration, authentication_layer, network_interface):
        self.rsa_key = rsa_private_key
        self.configuration = configuration
        self.network_interface = network_interface
        self.authentication_layer = authentication_layer

    @asyncio.coroutine
    def process_client_authentication(self, client):
        if self.authentication_layer.validate_machine_authentication(client.inbound_message, client.assigned_nonce):
            client.is_authorized = True
            if type(client.inbound_message) is bytes:
                client.inbound_message = client.inbound_message.decode('utf-8')
            client.rsa_key_digest = json.loads(client.inbound_message)["key_digest"]
            client.ephemeral_key_object = gateway_security.EphemeralKeyObject(
                self.configuration.diffie_hellman["p"],
                self.configuration.diffie_hellman["g"]
            )
            client.outbound_message = client.ephemeral_key_object.get_public_parameter_string()
        else:
            client.handshake_finished = True
        client.inbound_message = None
        return client

    @asyncio.coroutine
    def assign_cryptographic_interface(self, client):
        if client.inbound_message:
            client.ephemeral_key_object.compute_shared_secret(client.inbound_message)
            encryption_key = client.ephemeral_key_object.get_shared_key()
            peer_public_key = self.authentication_layer.get_public_key_by_digest(client.rsa_key_digest)
            if peer_public_key is not None:
                crypto_provider = gateway_security.MessageCryptography(encryption_key, self.rsa_key, peer_public_key)
                client.cryptographic_interface = crypto_provider
            else:
                print("[+] Unable to retrieve key, client is unauthorized.")
                client.is_authorized = False
        else:
            print("[+] No inbound message, client is unauthorized.")
            client.is_authorized = False
        client.inbound_message = None
        client.handshake_finished = True
        return client

    @asyncio.coroutine
    def callback(self, client):
        print("[+] Handshake callback.")
        if not client.is_authorized and not client.handshake_finished:
            if client.assigned_nonce is None:
                print("[+] Nonce is none, setting nonce.")
                client.assigned_nonce = self.authentication_layer.get_random_string()
                client.outbound_message = client.assigned_nonce
            elif client.rsa_key_digest is None and client.inbound_message:
                print("[+] Key digest is none, processing authentication.")
                client = yield from self.process_client_authentication(client)
        elif client.is_authorized and not client.handshake_finished:
            print("[+] Assigning cryptographic interface.")
            client = yield from self.assign_cryptographic_interface(client)
        if not client.is_authorized and client.handshake_finished:
            print("[+] Client is not authorized and handshake is finished.")
            yield from self.network_interface.dispose_client(client)
        yield from self.network_interface.handle_client(client)


class NetworkInterface:

    def __init__(self):
        self.active = False
        self.parser_callback = None
        self.handshake_provider = None
        self.client_queue = asyncio.Queue()

    @asyncio.coroutine
    def dispose_client(self, client):
        return

    @asyncio.coroutine
    def handle_client(self, client):
        yield from self.client_queue.put(client)

    @asyncio.coroutine
    def handle_transmit_message(self, client):
        if client.is_authorized and client.handshake_finished and client.outbound_message:
            client.outbound_message = client.cryptographic_interface.encrypt_message(client.outbound_message)
        if client.outbound_message:
            if type(client.outbound_message) is bytes:
                client.outbound_message = client.outbound_message.decode('utf-8')
            client.writer.write(bytes("{0}\n".format(client.outbound_message.strip()), 'utf-8'))
            yield from client.writer.drain()
            client.outbound_message = None
        return client

    @asyncio.coroutine
    def handle_receive_message(self, client):
        message = yield from client.reader.readline()
        if client.is_authorized and client.handshake_finished and message:
            message = client.cryptographic_interface.decrypt_message(message.decode('utf-8').strip())
        elif not message:
            yield from self.dispose_client(client)
            return None
        client.inbound_message = message.strip()
        return client

    @asyncio.coroutine
    def process_clients(self):
        if not self.active:
            self.active = True
        while self.active:
            if not self.client_queue.empty():
                client = yield from self.client_queue.get()
                if not client.handshake_finished:
                    yield from self.handshake_provider.callback(client)
                if client.outbound_message:
                    client = yield from self.handle_transmit_message(client)
                client = yield from self.handle_receive_message(client)
                if not client:
                    continue
                if client.handshake_finished and self.parser_callback is not None:
                    yield from self.parser_callback(self, client)
            else:
                yield from asyncio.sleep(1)

    @asyncio.coroutine
    def handle_new_client(self, reader, writer):
        client = ClientStateObject(reader, writer)
        yield from self.handle_client(client)


class ClientConnectionProvider:

    def __init__(self, local_auth_object, server_public_key):
        self.state_object = None
        self.server_public_key = server_public_key
        self.local_authentication = local_auth_object

    @asyncio.coroutine
    def _process_authentication_nonce(self):
        authentication_nonce = yield from self.receive(encrypted=False)
        authentication_string = self.local_authentication.get_machine_authentication_string(authentication_nonce)
        yield from self.transmit(authentication_string, encrypted=False)

    @asyncio.coroutine
    def _process_diffie_hellman_exchange(self):
        dh_public_parameters = yield from self.receive(encrypted=False)
        self.state_object.ephemeral_key_object = gateway_security.EphemeralKeyObject.from_public_parameter_string(
            dh_public_parameters.strip()
        )
        self.state_object.cryptographic_interface = gateway_security.MessageCryptography(
            secret_key=self.state_object.ephemeral_key_object.get_shared_key(),
            rsa_private_key=self.local_authentication.private_key,
            peer_public_key=self.server_public_key
        )
        yield from self.transmit(self.state_object.ephemeral_key_object.public_key(), encrypted=False)

    @asyncio.coroutine
    def transmit(self, message, encrypted=True):
        if encrypted and self.state_object.cryptographic_interface is not None:
            message = self.state_object.cryptographic_interface.encrypt_message(message).decode('utf-8')
        self.state_object.writer.write(bytes("{0}\n".format(message), 'utf-8'))
        yield from self.state_object.writer.drain()

    @asyncio.coroutine
    def receive(self, encrypted=True):
        message = yield from self.state_object.reader.readline()
        if encrypted and self.state_object.cryptographic_interface is not None:
            message = self.state_object.cryptographic_interface.decrypt_message(message.strip())
        if type(message) is bytes:
            message = message.decode('utf-8')
        return message.strip()

    @asyncio.coroutine
    def connect(self, ip_address, port):
        reader, writer = yield from asyncio.open_connection(ip_address, port)
        self.state_object = ClientStateObject(reader, writer)
        yield from self._process_authentication_nonce()
        yield from self._process_diffie_hellman_exchange()
