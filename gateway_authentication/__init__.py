import os
import json
import time
import uuid
import pyotp
import base64
import sqlite3
import binascii
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class ServerAuthenticationLayer:

    def __init__(self, database_file="authorized.db"):
        self.db_file = database_file
        self.response_pool = {}
        self.thread_pool = []
        self.query_queue = []
        self.db_handle = None
        self.active = False

    def _query_thread(self):
        self.db_handle = sqlite3.connect(self.db_file)
        cursor = self.db_handle.cursor()
        try:
            cursor.execute("CREATE TABLE authorized_users (username_digest,password_digest,otp_token,authorized)")
            cursor.execute("CREATE TABLE authorized_machines (machine_alias,machine_key_digest,public_key)")
        except sqlite3.OperationalError:
            pass
        cursor.close()
        self.db_handle.commit()
        while self.active:
            if len(self.query_queue) > 0:
                job_name, job_query, job_variables = self.query_queue[0]
                self.query_queue.pop(0)
                cursor = self.db_handle.cursor()
                cursor.execute(job_query, job_variables)
                response = cursor.fetchall()
                self.response_pool[job_name] = response
                cursor.close()
                self.db_handle.commit()
            else:
                time.sleep(0.5)

    def _execute_query(self, prepared_statement, statement_args):
        job_id = uuid.uuid4().hex
        query_parameters = (job_id, prepared_statement, statement_args)
        self.query_queue.append(query_parameters)
        while job_id not in self.response_pool:
            time.sleep(0.5)
        response = self.response_pool[job_id]
        del self.response_pool[job_id]
        return response

    @staticmethod
    def _compute_hash(data):
        hash_provider = Hash(SHA512(), default_backend())
        if type(data) is not bytes:
            data = bytes(data, "utf-8")
        hash_provider.update(data)
        return binascii.hexlify(hash_provider.finalize()).decode('utf-8')

    @staticmethod
    def get_random_string(length=32):
        return base64.b64encode(os.urandom(length * 2)).decode('utf-8').rstrip('=')[:length]

    def get_public_key_by_digest(self, key_digest):
        key_data = self._execute_query("SELECT public_key FROM authorized_machines WHERE machine_key_digest=? LIMIT 1",
                                       (key_digest,))
        if not key_data:
            return None
        else:
            key_data = key_data[0][0]
            public_key = serialization.load_pem_public_key(key_data, default_backend())
            return public_key

    def validate_machine_authentication(self, authentication_string, provided_nonce):
        # Ensure the input string is JSON and contains all required fields
        validate_set = ["key_digest", "nonce_digest", "signature"]
        try:
            if type(authentication_string) is bytes:
                authentication_string = authentication_string.decode('utf-8')
            authentication_dict = json.loads(authentication_string)
            for field in validate_set:
                field_value = authentication_dict[field]
                if not type(field_value) == str:
                    print("[!] Invalid data supplied in authentication string.")
                    raise ValueError
            # Ensure the nonce hash has been computed properly before continuing
            for i in range(0, 10000):
                provided_nonce = self._compute_hash(provided_nonce)
            if not provided_nonce == authentication_dict["nonce_digest"]:
                print(provided_nonce)
                print(authentication_dict["nonce_digest"])
                print("[!] Nonce digest does not match our digest of provided nonce.")
                raise ValueError
            # Check if we have a public key on file for the provided public key digest
            stored_machine_info = self._execute_query("SELECT * FROM authorized_machines "
                                                      "WHERE machine_key_digest=? LIMIT 1",
                                                      (authentication_dict["key_digest"],))
            if stored_machine_info:
                stored_machine_info = stored_machine_info[0]
            if len(stored_machine_info) == 3:
                # Verify the provided signature with the stored public key.
                public_key = serialization.load_pem_public_key(stored_machine_info[2], default_backend())
                public_key.verify(
                    base64.b64decode(authentication_dict["signature"]),
                    bytes(authentication_dict["nonce_digest"], 'utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(SHA512()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    SHA512()
                )
                print("[+] Authenticated machine with alias: {0}.".format(stored_machine_info[0]))
                return True
            else:
                raise LookupError("[!] Invalid data stored for provided public key.")
        except ValueError:
            print("[!] Value error during authentication, invalid JSON may have been supplied.")
            return False
        except KeyError:
            print("[!] Not all required fields present in authentication string, machine is not authorized.")
            return False
        except InvalidSignature:
            print("[!] Signature mismatch, machine is not authorized.")
            return False

    def validate_user_authentication(self, authentication_string):
        try:
            validate_set = ["username_digest", "passphrase_digest", "otp_token"]
            authentication_dict = json.loads(authentication_string)
            for field in validate_set:
                field_value = authentication_dict[field]
                if not type(field_value) == str:
                    print("[!] Invalid data supplied in authentication string.")
                    raise ValueError
            username_digest = authentication_dict["username_digest"]
            passphrase_digest = authentication_dict["passphrase_digest"]
            authentication_information = self._execute_query("SELECT * FROM authorized_users "
                                                             "WHERE username_digest=? LIMIT 1", (username_digest,))
            if authentication_information:
                authentication_information = authentication_information[0]
                if not authentication_information[1] == passphrase_digest:
                    print("[!] Passphrase digest mismatch, user is not authorized.")
                    return False
                otp_provider = pyotp.TOTP(authentication_information[2])
                if not otp_provider.verify(authentication_dict["otp_token"]):
                    print("[!] TOTP token mismatch, user is not authorized.")
                    return False
                print("[+] Provided credentials match stored user record, user will be authorized if account is active.")
                return authentication_information[3]
            else:
                print("[!] No matching username digest found, user is not authorized.")
                return False
        except KeyError:
            print("[!] Not all required fields present in authentication string, user is not authorized.")
            return False
        except ValueError:
            print("[!] Value error during authentication, invalid JSON may have been supplied.")
            return False

    def stop(self):
        self.active = False
        for thread in self.thread_pool:
            thread.join()
        return

    def start(self):
        self.active = True
        t = threading.Thread(target=self._query_thread)
        t.setDaemon(True)
        t.start()
        self.thread_pool.append(t)


class ClientAuthentication:

    def __init__(self, rsa_private_key_path):
        if os.path.isfile(rsa_private_key_path):
            with open(rsa_private_key_path, "r") as infile:
                pem_data = bytes(infile.read(), 'utf-8')
            self.private_key = serialization.load_pem_private_key(pem_data,
                                                                  password=None,
                                                                  backend=default_backend())
        else:
            raise FileNotFoundError("[!] Private key not found at path: {0}".format(rsa_private_key_path))

    @staticmethod
    def _compute_hash(data):
        hash_provider = Hash(SHA512(), default_backend())
        if type(data) is not bytes:
            data = bytes(data, "utf-8")
        hash_provider.update(data)
        return binascii.hexlify(hash_provider.finalize()).decode('utf-8')

    def get_pem_public_key(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8').split("\n")

    def get_public_key_digest(self):
        pem_public_key = self.get_pem_public_key()
        pem_public_key = [x for x in pem_public_key if len(x) > 0]
        pem_public_key.pop(0)
        pem_public_key.pop(-1)
        key_string = ''.join(pem_public_key)
        hash_provider = Hash(SHA512(), default_backend())
        hash_provider.update(bytes(key_string, 'utf-8'))
        return binascii.hexlify(hash_provider.finalize())

    def get_machine_authentication_string(self, authentication_nonce):
        nonce_digest = authentication_nonce
        for i in range(0, 10000):
            nonce_digest = self._compute_hash(nonce_digest)
        signature = self.private_key.sign(
            bytes(nonce_digest, 'utf-8'),
            padding.PSS(
                mgf=padding.MGF1(SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            SHA512()
        )
        authentication_dict = {
            "key_digest": self.get_public_key_digest().decode('utf-8'),
            "nonce_digest": nonce_digest,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        return json.dumps(authentication_dict)

    def get_user_authentication_string(self, username, passphrase, otp_token):
        for i in range(0, 10000):
            username = self._compute_hash(username)
            passphrase = self._compute_hash(passphrase)
        authentication_dict = {
            "username_digest": username,
            "passphrase_digest": passphrase,
            "otp_token": otp_token
        }
        return json.dumps(authentication_dict)