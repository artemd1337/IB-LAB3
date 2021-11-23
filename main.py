import argparse
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

settings = {
    'initial_file': '',
    'encrypted_file': '',
    'decrypted_file': '',
    'symmetric_key': '',
    'public_key': '',
    'secret_key': '',
}


def key_generation(symmetric_key_path, public_key_path, secret_key_path) -> None:
    symmetric_key = algorithms.SEED(os.urandom(16)).key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_key = key
    rsa_public_key = rsa_private_key.public_key()
    with open(public_key_path + 'public_key.pem', 'wb') as pub_file:
        pub_file.write(rsa_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo))

    with open(secret_key_path + 'private_key.pem', 'wb') as priv_file:
        priv_file.write(rsa_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.NoEncryption()))

    encrypted_symmetric_key = rsa_public_key.encrypt(symmetric_key,
                                                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))

    with open(symmetric_key_path + 'symmetric', 'wb') as key_file:
        key_file.write(encrypted_symmetric_key)


def decrypt_symmetric_key(path_to_symmetric: str, path_to_private) -> bytes:
    with open(path_to_symmetric, 'rb') as symmetric_file:
        enc_symmetric = symmetric_file.read()
    with open(path_to_private, 'rb') as private_file:
        private_key = serialization.load_pem_private_key(path_to_private.read(), password=None)
    symmetric_key = private_key.decrypt(enc_symmetric, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
    return symmetric_key


def encryption(file_to_encrypt: str, path_to_private: str, path_to_symmetric: str, path_to_encrypted_file: str) -> None:
    symmetric_key = decrypt_symmetric_key(path_to_symmetric, path_to_private)
    with open(file_to_encrypt, 'r', encoding='utf-8') as file_to_crypt:
        text = file_to_crypt.read()
    


key_generation('', '', '')
