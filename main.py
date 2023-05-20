from keys import generate_hybrid_keys
from encrypt import encrypt
from decrypt import decrypt
import warnings
if __name__ == '__main__':
    warnings.filterwarnings(
        action='ignore',
        category=UserWarning,
        message="IDEA has been deprecated",
    )
    sym_pth = "s.pem"
    pr_pth = "p.pem"
    pub_pth = "pu.pem"
    text_path = "bee_movie.txt"
    crypt_pth = "crt.txt"
    save_path = "save.txt"
    generate_hybrid_keys(sym_pth, pub_pth, pr_pth)
    encrypt(text_path, pr_pth, sym_pth, crypt_pth)
    decrypt(pr_pth, sym_pth, crypt_pth, save_path)

