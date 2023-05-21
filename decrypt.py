import os
import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as s_padding


def decrypt(key: bytes, encr_text_path: str, dcr_text_path: str) -> None:
    """
    Function for symmetric decryption
    :param key:
    :param encr_text_path:
    :param dcr_text_path:
    :return:
    """
    try:
        with open(encr_text_path, "rb") as f:
            c_text = f.read()
    except OSError as err:
        logging.warning(f'{err} during reading from {encr_text_path}')

    c_text, iv = c_text[8:], c_text[:8]
    cipher = Cipher(algorithms.IDEA(key), modes.CBC(iv))
    decrypter = cipher.decryptor()
    dc_text = decrypter.update(c_text) + decrypter.finalize()

    unpadder = s_padding.ANSIX923(64).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()

    try:
        with open(dcr_text_path, "w") as f:
            f.write(unpadded_dc_text.decode("UTF-8"))
            logging.info(f'Decrypted text has been written into {dcr_text_path}')
    except OSError as err:
        logging.warning(f'{err} during writing into {dcr_text_path}')


def decrypt_asymmetric(private_key_path: str, encr_key_path: str) -> bytes:
    """
    Function for asymmetric decryption
    Function decrypts symmetric key
    :param private_key_path:
    :param encr_key_path:
    :return: key
    """
    try:
        with open(private_key_path, 'rb') as pem_in:
            private_bytes = pem_in.read()
    except OSError as err:
        logging.warning(f'{err} during reading from {private_key_path}')
    try:
        with open(encr_key_path, 'rb') as pem_in:
            encr_key = pem_in.read()
    except OSError as err:
        logging.warning(f'{err} during reading from {private_key_path}')
    private_key = load_pem_private_key(private_bytes, password=None, )
    key = private_key.decrypt(encr_key,
                              padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                           label=None))
    return key
