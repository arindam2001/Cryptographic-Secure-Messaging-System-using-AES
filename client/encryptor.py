'''from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from shared.constants import AES_KEY_SIZE, AES_BLOCK_SIZE
from shared.crypto_utils import derive_key

def pad(data):
    pad_length = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + chr(pad_length) * pad_length

def encrypt_data(data, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad data before encryption
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data.encode())
    return encrypted_data, iv


    '''
'''
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from shared.constants import AES_KEY_SIZE, AES_BLOCK_SIZE
from shared.crypto_utils import derive_key

def pad(data):
    pad_length = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + chr(pad_length) * pad_length

def encrypt_message(data, password):
    
    salt = get_random_bytes(16)  # Generating salt for key derivation
    key = derive_key(password, salt)  # Deriving key using the password and salt
    iv = get_random_bytes(AES_BLOCK_SIZE)  # Separating IV for AES-CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad data and encrypt
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data.encode())
    return encrypted_data, iv, salt  # Return encrypted data, IV, and salt


def encrypt_username(data, password):
    # Calculate the byte length of the username in UTF-8 encoding
    byte_length = len(data.encode('utf-8'))
    

    # Check if username exceeds 16 bytes in UTF-8 encoding
    if byte_length > 16:
        print(f"Attention!! Username '{data}' length in bytes = {byte_length}")  # Debugging output
        raise ValueError("Username cannot exceed 16 bytes. Please use a shorter username.")
        
    
    salt = get_random_bytes(16)  # Generate salt for key derivation
    key = derive_key(password, salt)  # Derive key using the password and salt
    iv = get_random_bytes(AES_BLOCK_SIZE)  # Separate IV for AES-CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad data and encrypt
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data.encode())
    return encrypted_data, iv, salt  # Return encrypted data, IV, and salt

'''
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from shared.constants import AES_KEY_SIZE, AES_BLOCK_SIZE
from shared.crypto_utils import derive_key

def pad(data):
    pad_length = AES_BLOCK_SIZE - (len(data.encode('utf-8')) % AES_BLOCK_SIZE)
    padding = chr(pad_length) * pad_length
    return data + padding

def encrypt_message(data, password):
    salt = get_random_bytes(16)  
    key = derive_key(password, salt) 
    iv = get_random_bytes(AES_BLOCK_SIZE)  
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data).encode('utf-8')
    if len(padded_data) % AES_BLOCK_SIZE != 0:
        raise ValueError("Padded data length is not a multiple of AES block size (16 bytes).")
    encrypted_data = cipher.encrypt(padded_data) 
    return encrypted_data, iv, salt 

def encrypt_username(data, password):
    byte_length = len(data.encode('utf-8'))
    if byte_length > 16:
        raise ValueError("Username cannot exceed 16 bytes in UTF-8. Please use a shorter username.")
    salt = get_random_bytes(16)  
    key = derive_key(password, salt) 
    iv = get_random_bytes(AES_BLOCK_SIZE) 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data).encode('utf-8')
    if len(padded_data) % AES_BLOCK_SIZE != 0:
        raise ValueError("Padded data length is not a multiple of AES block size (16 bytes).")
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data, iv, salt  
