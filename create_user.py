import os
import sys
import pyotp
import getpass
import sqlite3
import pyqrcode
import binascii

from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.asymmetric import rsa


class Security:

    @staticmethod
    def compute_key_digest(key_data_array):
        # Clean empty lines
        key_data_array = [x for x in key_data_array if len(x) > 0]
        # Clean BEGIN and END tags
        key_data_array.pop(0)
        key_data_array.pop(-1)
        # Join the base64 string
        key_data = ''.join(key_data_array)
        hash_provider = Hash(SHA512(), default_backend())
        hash_provider.update(bytes(key_data, 'utf-8'))
        digest = binascii.hexlify(hash_provider.finalize()).decode('utf-8')
        return digest

    @staticmethod
    def compute_hash(data):
        hash_provider = Hash(SHA512(), default_backend())
        if type(data) is not bytes:
            data = bytes(data, "utf-8")
        hash_provider.update(data)
        return binascii.hexlify(hash_provider.finalize()).decode('utf-8')

if __name__ == "__main__":
    machine_alias = input("Authorized Machine Alias > ")
    sys.stdout.write("[+] Generating new RSA key pair.... ")
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    print("Done.\n[+] Serializing generated key data.")
    pem_data = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_data = rsa_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("[+] Writing private data to {0}.pem".format(machine_alias))
    with open("{0}.pem".format(machine_alias), "w") as outfile:
        outfile.write(pem_data.decode('utf-8'))
    print("[+] Computing public key digest.")
    pk_digest = Security.compute_key_digest(pub_data.decode('utf-8').split('\n'))
    sys.stdout.write("[+] Connecting to database... ")
    db_handle = sqlite3.connect("authorized.db")
    cursor = db_handle.cursor()
    print("Done.\n[+] Authorizing new machine information.")
    cursor.execute("INSERT INTO authorized_machines VALUES (?,?,?)", (machine_alias, pk_digest, pub_data))
    cursor.close()
    db_handle.commit()
    username = input("[+] Enter username, or press Enter to quit > ")
    try:
        if not username:
            raise Exception("No username provided, exiting.")
        passphrase = getpass.getpass("[+] Enter passphrase > ")
        if username and passphrase:
            username_digest = username
            sys.stdout.write("[+] Computing user and passphrase digests... ")
            for i in range(0, 10000):
                username_digest = Security.compute_hash(username_digest)
                passphrase = Security.compute_hash(passphrase)
            print("Done.\n[+] Creating TOTP token for new user.")
            otp_token = pyotp.random_base32()
            totp_object = pyotp.TOTP(otp_token)
            print("[+] Formatting provisioning URI.")
            uri = pyotp.TOTP.provisioning_uri(totp_object, "{0}@remote-access.bit".format(username))
            qr_image = pyqrcode.create(uri)
            qr_image.png("{0}-2FA.png".format(username), scale=10)
            print("[+] TOTP provisioning URI saved as {0}-2FA.png".format(username))
            # Render the QR code in the terminal on Linux systems
            if not os.name == "nt":
                print(qr_image.terminal(quiet_zone=1))
            sys.stdout.write("[+] Authorizing new user information... ")
            cursor = db_handle.cursor()
            cursor.execute("INSERT INTO authorized_users VALUES (?,?,?,?)",
                           (username_digest, passphrase, otp_token, True))
            cursor.close()
            db_handle.commit()
            print("Done.\n[+] User creation operations completed.")
    except Exception as e:
        print("[!] {0}".format(e))
        pass
    finally:
        sys.stdout.write("[+] Closing database handle.... ")
        db_handle.close()
        print("Done.")
    print("[+] All operations completed successfully.")
