from keys import *
from encrypt import *
from decrypt import *
import warnings
logger = logging.getLogger()
logger.setLevel('INFO')

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
    key = generate_symmetric_key(16)
    public_key = generate_asymmetric_key(pub_pth, pr_pth)
    encrypt_symmetric_key(public_key, key)
    encrypt(text_path, key, crypt_pth)
    decrypt(key, crypt_pth, save_path)

