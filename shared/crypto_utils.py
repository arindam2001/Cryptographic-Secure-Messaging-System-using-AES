from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from shared.constants import AES_KEY_SIZE

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=AES_KEY_SIZE)

def generate_iv():
    return get_random_bytes(16)
