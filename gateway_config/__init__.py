import os
import json


_validate_set = [
    "client_port",
    "gatekeeper_port",
    "administration_port",
    "bind_address",
    "tor_path",
    "torrc_path",
    "authentication_database",
    "private_key",
    "diffie-hellman"
]


class ConfigurationObject:

    def __init__(self):
        self.diffie_hellman = {
            "p": "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF951"
                 "9B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A"
                 "899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD9"
                 "61C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B27"
                 "83A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFF"
                 "FFFFFFF",
            "g": 2
        }
        self.client_port = 48020
        self.gatekeeper_port = 48021
        self.administration_port = 48022
        self.bind_address = "0.0.0.0"
        self.tor_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tor", "tor.exe")
        self.torrc_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tor", "torrc")
        self.private_key = os.path.join(os.path.dirname(os.path.realpath(__file__)), "machine_key.pem")
        self.authentication_database = os.path.join(os.path.dirname(os.path.realpath(__file__)), "authorized.db")

    def get_item(self, key):
        if key not in _validate_set:
            raise KeyError("Requested value of invalid configuration item: {0}".format(key))
        if key == "client_port":
            return self.client_port
        elif key == "gatekeeper_port":
            return self.gatekeeper_port
        elif key == "administration_port":
            return self.administration_port
        elif key == "bind_address":
            return self.bind_address
        elif key == "tor_path":
            return self.tor_path
        elif key == "torrc_path":
            return self.torrc_path
        elif key == "authentication_database":
            return self.authentication_database
        elif key == "private_key":
            return self.private_key
        elif key == "diffie-hellman":
            return self.diffie_hellman
        else:
            raise KeyError("Requested configuration item not configured in get_item function: {0}".format(key))

    def set_item(self, key, value):
        if key not in _validate_set:
            raise KeyError("Invalid configuration item supplied: {0}".format(key))
        if key == "client_port":
            self.client_port = value
        elif key == "gatekeeper_port":
            self.gatekeeper_port = value
        elif key == "administration_port":
            self.administration_port = value
        elif key == "bind_address":
            self.bind_address = value
        elif key == "tor_path":
            self.tor_path = value
        elif key == "torrc_path":
            self.torrc_path = value
        elif key == "private_key":
            self.private_key = value
        elif key == "authentication_database":
            self.authentication_database = value
        elif key == "diffie-hellman":
            self.diffie_hellman = value
        else:
            raise KeyError("Configuration item not configured in set_item function: {0}".format(key))


class GatewayConfiguration:

    @staticmethod
    def load_from_file(file_path):
        if os.path.isfile(file_path):
            with open(file_path, "r") as infile:
                serialized_configuration = infile.read()
            config_data = json.loads(serialized_configuration)
            for config_item in _validate_set:
                if config_item not in config_data:
                    raise KeyError("Configuration item not set: {0}".format(config_item))
            configuration_object = ConfigurationObject()
            for key in _validate_set:
                configuration_object.set_item(key, config_data[key])
            return configuration_object
        else:
            raise FileNotFoundError("Configuration file not located at path: {0}".format(file_path))

    @staticmethod
    def save_to_file(file_path, config_object):
        config_dict = {}
        for item in _validate_set:
            config_dict[item] = config_object.get_item(item)
        with open(file_path, "w") as outfile:
            outfile.write(json.dumps(config_dict))
