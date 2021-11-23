import argparse
import json
import pickle
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as text_padding

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
        private_key = serialization.load_pem_private_key(private_file.read(), password=None)
    symmetric_key = private_key.decrypt(enc_symmetric, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
    return symmetric_key


def encryption(file_to_encrypt: str, path_to_private: str, path_to_symmetric: str, path_to_encrypted_file: str) -> None:
    symmetric_key = decrypt_symmetric_key(path_to_symmetric, path_to_private)
    with open(file_to_encrypt, 'r', encoding='utf-8') as file_to_crypt:
        text = file_to_crypt.read()
    padder = text_padding.ANSIX923(128).padder()
    text = bytes(text, 'utf-8')
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    enc_text = encryptor.update(padded_text) + encryptor.finalize()
    data = {'enc_text': enc_text, 'iv': iv}
    with open(path_to_encrypted_file, 'wb') as enc_file:
        pickle.dump(data, enc_file)


def decryption(path_to_enc_file: str, path_to_private: str, path_to_symmetric: str, path_to_dec_file: str) -> None:
    symmetric_key = decrypt_symmetric_key(path_to_symmetric, path_to_private)
    with open(path_to_enc_file, 'rb') as enc_file:
        data = pickle.load(enc_file)
    iv = data['iv']
    ciphertext = data['enc_text']
    cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
    decrypt = cipher.decryptor()
    dec_text = decrypt.update(ciphertext) + decrypt.finalize()
    unpadder = text_padding.ANSIX923(128).unpadder()
    unpadded_dec_text = unpadder.update(dec_text) + unpadder.finalize()
    with open(path_to_dec_file, 'w') as dec_file:
        dec_file.write(str(unpadded_dec_text.decode("utf-8")))


key_generation('', '', '')
encryption('file_to_encode.txt', 'private_key.pem', 'symmetric', 'encrypted_text.txt')
decryption('encrypted_text.txt', 'private_key.pem', 'symmetric', 'decoded_text.txt ')
