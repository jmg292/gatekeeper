import os
import json
import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import OFB
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES


class EphemeralKeyObject:

    def __init__(self, p, g):
        if type(p) is str:
            p = int(p, 16)
        self.p = p
        self.g = g
        self.shared_secret = None
        self.s = self._generate_secret()

    def public_key(self):
        return pow(self.g, self.s, self.p)

    def get_public_parameter_string(self):
        public_parameters = {
            "p": self.p,
            "g": self.g,
            "public_key": self.public_key()
        }
        return base64.b64encode(json.dumps(public_parameters).encode('utf-8'))

    def compute_shared_secret(self, peer_key):
        if type(peer_key) is bytes:
            peer_key = int(peer_key.decode('utf-8'))
        self.shared_secret = pow(peer_key, self.s, self.p)
        return self.shared_secret

    def get_shared_key(self, key_length=32, shared_secret=None):
        if not shared_secret and not self.shared_secret:
            raise ArithmeticError("No shared secret provided.")
        elif shared_secret and not self.shared_secret:
            self.shared_secret = shared_secret
        hash_provider = HMAC(hex(self.shared_secret).encode('utf-8'), SHA512(), default_backend())
        for i in range(0, 10000):
            hash_provider.update(hex(i).encode('utf-8'))
        shared_digest = base64.b64encode(hash_provider.finalize())
        return shared_digest[:key_length]

    @staticmethod
    def _generate_secret(max_int=(2**64) - 1):
        random_seed = int(binascii.hexlify(os.urandom(32)), 16)
        if random_seed < 0:
            random_seed *= -1
        return random_seed % max_int

    @staticmethod
    def from_public_parameter_string(parameter_string):
        public_parameters = json.loads(base64.b64decode(parameter_string).decode('utf-8'))
        key_object = EphemeralKeyObject(public_parameters["p"], public_parameters["g"])
        key_object.compute_shared_secret(public_parameters["public_key"])
        return key_object


class MessageCryptography:

    def __init__(self, secret_key, rsa_private_key, peer_public_key):
        self.secret_key = secret_key
        self.rsa_private_key = rsa_private_key
        self.peer_public_key = peer_public_key

    @staticmethod
    def _get_ciphertext_digest(ciphertext):
        if type(ciphertext) is str:
            ciphertext = bytes(ciphertext, 'utf-8')
        hash_provider = Hash(SHA512(), default_backend())
        hash_provider.update(ciphertext)
        return base64.b64encode(hash_provider.finalize()).decode('utf-8').rstrip("=")

    def _sign_ciphertext_digest(self, ciphertext_digest):
        if type(ciphertext_digest) is str:
            ciphertext_digest = bytes(ciphertext_digest, 'utf-8')
        return base64.b64encode(self.rsa_private_key.sign(ciphertext_digest,
                                                          padding.PSS(
                                                              mgf=padding.MGF1(SHA512()),
                                                              salt_length=padding.PSS.MAX_LENGTH
                                                          ), SHA512())).decode('utf-8')

    def _signature_is_valid(self, ciphertext_digest, encoded_signature):
        if type(encoded_signature) is str:
            encoded_signature = bytes(encoded_signature, 'utf-8')
        if type(ciphertext_digest) is str:
            ciphertext_digest = bytes(ciphertext_digest, 'utf-8')
        signature = base64.b64decode(encoded_signature)
        try:
            self.peer_public_key.verify(
                signature,
                ciphertext_digest,
                padding.PSS(
                    mgf=padding.MGF1(SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                SHA512()
            )
            return True
        except InvalidSignature:
            return False

    def _encrypt_aes_ofb(self, data):
        if type(data) is str:
            data = bytes(data, "utf-8")
        iv = os.urandom(16)
        # Using Output Feedback Mode to ease compatibility with the .NET crypto library
        cipher = Cipher(AES(self.secret_key), OFB(iv), default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')

    def _decrypt_aes_ofb(self, encoded_ciphertext, encoded_iv):
        iv = base64.b64decode(encoded_iv)
        ciphertext = base64.b64decode(encoded_ciphertext)
        cipher = Cipher(AES(self.secret_key), OFB(iv), default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def encrypt_message(self, plaintext):
        iv, ciphertext = self._encrypt_aes_ofb(plaintext)
        message_digest = self._get_ciphertext_digest(ciphertext)
        message_signature = self._sign_ciphertext_digest(message_digest)
        message_dict = {
            "iv": iv,
            "message": ciphertext,
            "digest": message_digest,
            "signature": message_signature
        }
        return base64.b64encode(json.dumps(message_dict).encode('utf-8'))

    def decrypt_message(self, serialized_ciphertext):
        return_value = None
        if type(serialized_ciphertext) is bytes:
            serialized_ciphertext = serialized_ciphertext.decode('utf-8')
        ciphertext = json.loads(base64.b64decode(serialized_ciphertext).decode('utf-8'))
        computed_digest = self._get_ciphertext_digest(ciphertext["message"])
        if computed_digest == ciphertext["digest"]:
            if self._signature_is_valid(computed_digest, ciphertext["signature"]):
                return_value = self._decrypt_aes_ofb(ciphertext["message"], ciphertext["iv"])
            else:
                print("[!] Signature mismatch.")
        else:
            print("[!] Digest mismatch.")
        return return_value.decode('utf-8')
