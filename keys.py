import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_hybrid_keys(symmetric_path: str, public_key_path: str, private_key_path: str) -> None:
    """
    This function generates all necessary keys
    :param symmetric_path:
    :param public_key_path:
    :param private_key_path:
    :return:
    """
    key = os.urandom(16)
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    with open(public_key_path, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))

    with open(private_key_path, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    encr_key = public_key.encrypt(key,
                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                               label=None))

    with open(symmetric_path, 'wb') as key_file:
        key_file.write(encr_key)


def generate_symmetric_key(key_length: int) -> bytes:
    """
    Function generates key for symmetric encryption
    :param key_length:
    """
    key = os.urandom(key_length)
    logging.info("Symmetric key has been generated")
    return key


def write_encrypted_key(symmetric_path: str, encr_key: bytes) -> None:
    """
    Function writes encrypted symmetric key into file
    :param symmetric_path:
    :param encr_key:
    """
    try:
        with open(symmetric_path, 'wb') as key_file:
            key_file.write(encr_key)
        logging.info(f'key has been written into {symmetric_path}!')
    except OSError as err:
        logging.warning(f'{err} Error during writing into {symmetric_path}!')


def generate_asymmetric_key(public_key_path: str, private_key_path: str) -> bytes:
    """
    Function generates asymmetric keys and writes them into files.
    :param public_key_path:
    :param private_key_path:
    :return:
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

