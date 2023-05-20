import os
from cryptography.hazmat.primitives import padding as s_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt(path_to_text: str, private_key_path: str, symmetric_key_path: str, save_path: str) -> None:
    if os.path.isfile(path_to_text) is False:
        print("Invalid path to text")
        return
    if os.path.isfile(private_key_path) is False:
        print("Invalid private key path")
        return
    if os.path.isfile(symmetric_key_path) is False:
        print("Invalid symmetric key path")
        return

    with open(symmetric_key_path, mode='rb') as key_file:
        encr_key = key_file.read()

    with open(private_key_path, 'rb') as pem_in:
        private_bytes = pem_in.read()

    private_key = load_pem_private_key(private_bytes, password=None, )

    key = private_key.decrypt(encr_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(), label=None))

    with open(path_to_text, "r", encoding="UTF-8") as f:
        text = f.read()

    padder = s_padding.ANSIX923(64).padder()
    padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()

    iv = os.urandom(8)
    cipher = Cipher(algorithms.IDEA(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()

    with open(save_path, "wb") as f:
        f.write(c_text)


