import argparse
import pickle
import json
import os
from tqdm import tqdm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as text_padding


def key_generation(symmetric_key_path: str, public_key_path: str, secret_key_path: str) -> None:
    """
    Функция генерирует ключ симмметричного алгоритма, генерирует открытые и закрытые ключи ассиметричного алгоритма,
    шифрует ключ симметричного алгоритма и сохраняет все ключи по указанным путям
    :param symmetric_key_path: Путь к зашифрованному симметричному ключу
    :param public_key_path: Путь к октрытому ключу ассиметрического шифра
    :param secret_key_path: Путь к приватному ключу ассимтерического шифра
    :return: None
    """
    # Генерация симметричного ключа
    symmetric_key = algorithms.SEED(os.urandom(16)).key
    # Генерация ассиметричных ключей
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_key = key
    rsa_public_key = rsa_private_key.public_key()
    with open(public_key_path, 'wb') as pub_file:
        pub_file.write(rsa_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo))

    with open(secret_key_path, 'wb') as priv_file:
        priv_file.write(rsa_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.NoEncryption()))
    # Шифрование симметричного ключа
    encrypted_symmetric_key = rsa_public_key.encrypt(symmetric_key,
                                                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))

    with open(symmetric_key_path, 'wb') as key_file:
        key_file.write(encrypted_symmetric_key)


def decrypt_symmetric_key(path_to_symmetric: str, path_to_private: str) -> bytes:
    """
    Дешифрует ключ симметричного шифрования
    :param path_to_symmetric: Путь к зашифрованному симметричному ключу
    :param path_to_private: Путь к приватному ключу, которым был зашифрован симметричный ключ
    :return: Расшифрованный симметричный ключ
    """
    with open(path_to_symmetric, 'rb') as symmetric_file:
        enc_symmetric = symmetric_file.read()
    with open(path_to_private, 'rb') as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None)
    # Дешифрование
    symmetric_key = private_key.decrypt(enc_symmetric, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
    return symmetric_key


def encryption(file_to_encrypt: str, path_to_private: str, path_to_symmetric: str, path_to_encrypted_file: str) -> None:
    """
    Шифрует файл по указанному пути и сохраняет зашифрованный файл
    :param file_to_encrypt: Путь к файлу, который необходимо зашифровать
    :param path_to_private: Путь к файлу с приватным ключом
    :param path_to_symmetric: Путь к файлу с зашифрованным симметричным ключом
    :param path_to_encrypted_file: Путь по которому сохранить зашифрованный файл
    :return: None
    """
    # Дешифровка симметричного ключа
    symmetric_key = decrypt_symmetric_key(path_to_symmetric, path_to_private)
    with open(file_to_encrypt, 'r', encoding='utf-8') as file_to_crypt:
        text = file_to_crypt.read()
    # Паддинг исходного файла
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
    """
    Дешифрует файл по указанному пути и сохраняет расшифрованный файл
    :param path_to_enc_file: Путь до зашифрованного файла
    :param path_to_private: Путь до приватного ключа
    :param path_to_symmetric: Путь до симметричного кода
    :param path_to_dec_file: Путь, куда следует сохранить расшифрованный файл
    :return: None
    """
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='main.py')
    parser.add_argument('-s', '--settings', type=str, help='Путь к файлу, в котором содержатся настройки',
                        required=True, dest='settings_path')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encryption', help='Шифрование файла', default=None, dest='enc')
    group.add_argument('-d', '--decryption', help='Дешифрование файла', default=None, dest='dec')
    group.add_argument('-g', '--generate', help='Генерация ключей', default=None, dest='gen')
    args = parser.parse_args()
    read_data_from = os.path.realpath(args.settings_path)
    try:
        with open(read_data_from) as fp:
            json_data = json.load(fp)
    except:
        os.error("Settings path error")
    if args.gen is not None:
        key_generation(json_data['symmetric_key'], json_data['public_key'], json_data['secret_key'])
    if args.enc is not None:
        with tqdm(100, desc='Encrypting your file: ') as progressbar:
            encryption(json_data['initial_file'], json_data['secret_key'], json_data['symmetric_key'],
                       json_data['encrypted_path'])
            progressbar.update(100)
    if args.dec is not None:
        with tqdm(100, desc='Decrypting your file: ') as progressbar:
            decryption(json_data['encrypted_file'], json_data['secret_key'], json_data['symmetric_key'],
                       json_data['decrypted_file'])
            progressbar.update(100)
