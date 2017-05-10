import os
import asyncio
import gateway_config
import gateway_networking
import gateway_authentication


@asyncio.coroutine
def echo_callback(network_interface, client):
    client.outbound_message = client.inbound_message
    client.inbound_message = None
    yield from network_interface.handle_client(client)


class NetworkHandler:

    def __init__(self, private_key, config, auth_layer):
        self.configuration = config
        self.private_key = private_key
        self.authentication_layer = auth_layer

    def launch_client_handler(self):
        print("[+] Instantiating client network interface.")
        network_iface = gateway_networking.NetworkInterface()
        print("[+] Instantiating client cryptographic handshake provider.")
        handshake_provider = gateway_networking.HandshakeInterface(self.private_key, self.configuration,
                                                                   self.authentication_layer, network_iface)
        network_interface.handshake_provider = handshake_provider
        print("[+] Instantiating client protocol handler.")
        print("[+] Registering client protocol callback handler.")
        # TODO: Client protocol handler, register callback
        print("[+] Launching client handler event loop.")
        event_loop = asyncio.get_event_loop()


if __name__ == "__main__":
    test_message = "This is a test message."
    config_object = gateway_config.ConfigurationObject()
    config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "configuration.json")
    if os.path.isfile(config_path):
        print("[+] Attempting to load local configuration file...")
        config_object = gateway_config.GatewayConfiguration.load_from_file("configuration.json")
        print("[+] Successfully loaded configuration from file.")
    else:
        print("[+] No configuration file found, generating file from default configuration.")
        gateway_config.GatewayConfiguration.save_to_file(config_path, config_object)
        print("[+] Configuration saved to path: {0}".format(config_path))
    print("[+] Network Interface Test - Initializing authentication layer.")
    authentication_layer = gateway_authentication.ServerAuthenticationLayer(config_object.authentication_database)
    authentication_layer.start()
    print("[+] Loading local RSA key.")
    local_authentication = gateway_authentication.ClientAuthentication(config_object.private_key)
    print("[+] Instantiating network interface.")
    network_interface = gateway_networking.NetworkInterface()
    print("[+] Instantiating handshake interface.")
    handshake_interface = gateway_networking.HandshakeInterface(local_authentication.private_key, config_object,
                                                                authentication_layer, network_interface)
    network_interface.handshake_provider = handshake_interface
    network_interface.parser_callback = echo_callback
    print("[+] Instantiating async event loop.")
    loop = asyncio.get_event_loop()
    print("[+] Binding server to {0}:{1}.".format(config_object.bind_address, config_object.client_port))
    loop.run_until_complete(asyncio.gather(
        network_interface.process_clients(),
        asyncio.start_server(
            network_interface.handle_new_client,
            config_object.bind_address,
            config_object.client_port
        )
    ))
    print("[+] All operations finished, terminating application.")
    authentication_layer.stop()
