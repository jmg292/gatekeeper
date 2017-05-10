import asyncio
import gateway_config
import gateway_networking
import gateway_authentication

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


@asyncio.coroutine
def dummy_terminal(connection_provider):
    message = "start"
    while not message.lower() == "exit":
        message = input("> ").strip()
        yield from connection_provider.transmit(message)
        response = yield from connection_provider.receive()
        print("[+] Response: {0}".format(response))


if __name__ == "__main__":
    addr = "10.0.0.139"
    print("[+] Initializing test client.")
    config_object = gateway_config.GatewayConfiguration.load_from_file("configuration.json")
    local_authentication = gateway_authentication.ClientAuthentication("TestUser2.pem")
    print("[+] Loading server public key.")
    with open("DevelopmentMachine.pub", "rb") as infile:
        key_data = infile.read()
    public_key = serialization.load_pem_public_key(
        key_data, default_backend()
    )
    print("[+] Instantiating client connection interface.")
    connection_provider = gateway_networking.ClientConnectionProvider(local_authentication, public_key)
    print("[+] Instantiating base event loop.")
    loop = asyncio.get_event_loop()
    print("[+] Connecting to server at {0}:{1}".format(addr, config_object.client_port))
    connection = loop.run_until_complete(connection_provider.connect(addr, config_object.client_port))
    loop.run_until_complete(dummy_terminal(connection_provider))
