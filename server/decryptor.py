from Crypto.Cipher import AES
from database import retrieve_message
from shared.crypto_utils import derive_key
from shared.constants import AES_BLOCK_SIZE

def decrypt_data(message_id, password):
    data = retrieve_message(message_id)
    if not data:
        print("Invalid Message ID.")
        return
    encrypted_username, encrypted_message, username_iv, message_iv, username_salt, message_salt = data  
    username = decrypt_component(encrypted_username, username_iv, password, username_salt)
    message = decrypt_component(encrypted_message, message_iv, password, message_salt)
    
    if username is not None and message is not None:
        print(f"Decrypted Username: {username}")
        print(f"Decrypted Message: {message if message else '[Empty Message]'}")
    else:
        print("Decryption failed. Invalid password.")


def decrypt_component(encrypted_data, iv, password, salt):
    key = derive_key(password, salt)  
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    pad_length = padded_data[-1]
    if pad_length > AES_BLOCK_SIZE:
        return None
    unpadded_data = padded_data[:-pad_length]
    try:
        return unpadded_data.decode('utf-8')
    except UnicodeDecodeError:
        return None
