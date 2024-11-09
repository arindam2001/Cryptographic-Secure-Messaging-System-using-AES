import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import getpass
import socket
from encryptor import encrypt_message, encrypt_username
from shared.config import SERVER_IP, SERVER_PORT

def main():
    while True:
        try:
            username = input("Enter Username: ")
            if not username.strip():
                raise ValueError("Attention!! Username cannot be empty. Please enter a valid username.\nPlease enter a username that is 16 bytes or less.\n")
            password = getpass.getpass("Enter Password: ")
            if not password.strip():
                raise ValueError("Attention!! Password cannot be empty. Please enter a valid Password.")
            message = input("Enter Message: ")
            encrypted_username, username_iv, username_salt = encrypt_username(username, password)
            encrypted_message, message_iv, message_salt = encrypt_message(message, password)
            data_packet = {
                'user_id': encrypted_username,
                'username_iv': username_iv,
                'username_salt': username_salt,
                'message': encrypted_message,
                'message_iv': message_iv,
                'message_salt': message_salt
            }
            '''with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_IP, SERVER_PORT))
                s.sendall(str(data_packet).encode())
                print("Message sent securely!")'''
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((SERVER_IP, SERVER_PORT))
                    s.sendall(str(data_packet).encode())
                    print("Message sent securely!")
            except socket.error:
                print("OOPS!! Server Down. Message not sent.")
            print()
            print()
        except ValueError as e:
            print("Error:", e)
        
if __name__ == "__main__":
    main()
