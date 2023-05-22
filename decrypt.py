import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as s_padding


def decrypt_symmetric(key: bytes, encr_text_path: str, dcr_text_path: str) -> None:
    """
    Function for symmetric decryption
    :param key: Key for symmetric decryption
    :param encr_text_path: Location of encrypted text
    :param dcr_text_path: Location where decrypted text will be saved
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



