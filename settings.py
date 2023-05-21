import json

settings = {
    "text_file": "data/bee_movie.txt",
    "encrypted_file": "data/encrypted_file.txt",
    "decrypted_file": "data/decrypted_file.txt",
    "symmetric_key": "data/symmetric_key.txt",
    "public_key": "data/public_key.pem",
    "private_key": "data/private_key.pem"
}

if __name__ == "__main__":
    with open("data/settings.json", "w") as file:
        json.dump(settings, file)