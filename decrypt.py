import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def decrypt(private_key_path: str, symmetric_key_path: str, encr_text_path: str, dcr_text_path: str) -> None:
    if os.path.isfile(encr_text_path) is False:
        print("Invalid path to text")
        return
    if os.path.isfile(private_key_path) is False:
        print("Invalid private key path")
        return
    if os.path.isfile(symmetric_key_path) is False:
        print("Invalid symmetric key path")
        return
    if os.path.isdir(dcr_text_path) is False:
        print("Invalid save path")
        return
    with open(symmetric_key_path, mode='rb') as key_file:
        encr_key = key_file.read()

    with open(private_key_path, 'rb') as pem_in:
        private_bytes = pem_in.read()

    private_key = load_pem_private_key(private_bytes, password=None, )

    key = private_key.decrypt(encr_key,
                              padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                           label=None))
    with open(encr_text_path, "r") as f:
        c_text = f.read()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.IDEA(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    c_text = bytes(c_text)
    dc_text = decryptor.update(c_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(32).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()

    with open(dcr_text_path, "w") as f:
        f.write(unpadded_dc_text.decode("UTF-8"))


