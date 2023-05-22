import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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

