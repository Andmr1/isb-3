from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import logging
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def generate_symmetric_key(key_length: int) -> bytes:
    """
    Function generates key for symmetric encryption
    :param key_length: Length of generated key
    """
    key = os.urandom(key_length)
    logging.info("Symmetric key has been generated")
    return key


def generate_asymmetric_key(public_key_path: str, private_key_path: str) -> bytes:
    """
    Function generates asymmetric keys and writes them into files.
    :param public_key_path:Location where public key will be saved
    :param private_key_path:Location where private key will be saved
    :return: public key
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    try:
        with open(public_key_path, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
            logging.info(f'Public key has been written into {public_key_path}')
    except OSError as err:
        logging.warning(f'{err} Error during writing into {public_key_path}!')
    try:
        with open(private_key_path, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
            logging.info(f'Private key has been written into {private_key_path}')
    except OSError as err:
        logging.warning(f'{err} Error during writing into {private_key_path}!')
    return public_key


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


def decrypt_asymmetric(private_key_path: str, encr_key_path: str) -> bytes:
    """
    Function for asymmetric decryption
    Function decrypts symmetric key
    :param private_key_path: Location of a private key
    :param encr_key_path: Location of encrypted symmetric key
    :return key: Decrypted symmetric key
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
