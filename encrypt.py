import logging
import os
from cryptography.hazmat.primitives import padding as s_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt_symmetric(path_to_text: str, symmetric_key: bytes, save_path: str) -> None:
    """
    Function encrypts text from "path_to_text" and saves it into "save_path"
    :param path_to_text: Location of unencrypted text
    :param symmetric_key: Key for symmetric encryption
    :param save_path: Location where encrypted text will be saved
    :return:
    """
    try:
        with open(path_to_text, "r", encoding="UTF-8") as f:
            text = f.read()
    except OSError as err:
        logging.warning(f'{err} during reading from {path_to_text}')

    padder = s_padding.ANSIX923(64).padder()
    padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()

    iv = os.urandom(8)
    cipher = Cipher(algorithms.IDEA(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()

    try:
        with open(save_path, "wb") as f:
            f.write(c_text)
            logging.info(f'Encrypted text has been written into {save_path}')
    except OSError as err:
        logging.warning(f'{err} during writing to {save_path}')


def encrypt_asymmetric(public_key: bytes, key: bytes) -> bytes:
    """
    Symmetric key encryption
    :param public_key:
    :param key: Key for symmetric encryption
    :return:
    """
    encr_key = public_key.encrypt(key,
                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                               label=None))
    logging.info(f'Symmetric key has been encrypted')
    return encr_key
