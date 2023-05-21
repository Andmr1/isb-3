from keys import *
from encrypt import *
from decrypt import *
import warnings
import argparse
from read import *
logger = logging.getLogger()
logger.setLevel('INFO')
SETTINGS_FILE = "data/settings.json"

if __name__ == '__main__':
    warnings.filterwarnings(
        action='ignore',
        category=UserWarning,
        message="IDEA has been deprecated",
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("-set", "--settings", type=str, default=SETTINGS_FILE,
                        help="Allows to use your own json file ")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-gen", "--generation",
                       help="Generate keys", action="store_true")
    group.add_argument("-enc", "--encryption",
                       help="Encryption", action="store_true")
    group.add_argument("-dec", "--decryption",
                       help="Decryption", action="store_true")
    args = parser.parse_args()
    settings = read_settings(args.settings)
    if args.generation:
        public_key = generate_asymmetric_key(settings["public_key"], settings["private_key"])
        symmetric_key = generate_symmetric_key(16)
        encrypted_symmetric_key = encrypt_symmetric_key(public_key, symmetric_key)
        write_encrypted_key(settings["symmetric_key"], encrypted_symmetric_key)
    elif args.encryption:
        symmetric_key = decrypt_asymmetric(settings["private_key"], settings["symmetric_key"])
        encrypt(settings["text_file"], symmetric_key, settings["encrypted_file"])
    elif args.decryption:
        symmetric_key = decrypt_asymmetric(settings["private_key"], settings["symmetric_key"])
        decrypt(symmetric_key, settings["encrypted_file"], settings["decrypted_file"])
