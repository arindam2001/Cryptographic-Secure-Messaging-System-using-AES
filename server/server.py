import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import getpass
import threading
import socket
import configparser
from database import setup_database, store_message, fetch_all_messages, count_total_messages, retrieve_message
from decryptor import decrypt_data
from shared.config import SERVER_IP, SERVER_PORT

def display_messages():
    messages = fetch_all_messages()
    if not messages:
        print("No message received")
    else:
        print("\nID | Encrypted Username | Encrypted Message | Timestamp")
        print("-" * 50)
        for row in messages:
            print(f"{row[0]} | {row[1]} | {row[2]} | {row[7]}")  

def handle_new_messages():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_IP, SERVER_PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024).decode()
                if data:
                    data_packet = eval(data) 
                    store_message(
                        data_packet['user_id'],
                        data_packet['message'],
                        data_packet['username_iv'],
                        data_packet['message_iv'],
                        data_packet['username_salt'],
                        data_packet['message_salt']
                    )
                    total_message_count = count_total_messages()  
                    if total_message_count!=1:
                        display_messages()
                        print("Enter Message ID to view, 'delete <ID>' to delete a message, 'drop table' to delete all messages, or 'exit' to quit: ")

'''def prompt_user_for_decryption():
    
    while True:
        total_message_count = count_total_messages()  
        display_messages()
        print(f"\nTotal message received: {total_message_count}")
        
        message_id = input("Enter Message ID to view (or type 'exit' to quit): ")
        if message_id.lower() == 'exit':
            break
        data = retrieve_message(message_id)
        if not data:
            print("Invalid message ID!")
        else:
            #password = input("Enter Password: ")
            password = getpass.getpass("Enter Password: ")

            decrypt_data(int(message_id), password)
'''

def verify_master_password(master_password):
    user_password = getpass.getpass("Enter Master Password: ")
    return user_password == master_password
def prompt_user_for_decryption():
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
    master_password = config.get("admin", "master_password")
    while True:
        total_message_count = count_total_messages()
        if total_message_count == 0:
            command = input("No messages received. Type 'exit' to stop or press Enter to check for new messages:\n")
            if command.lower() == 'exit':
                print("Exiting...")
                break  
            else:
                continue  
        display_messages()
        command = input("Enter Message ID to view, 'delete <ID>' to delete a message, 'drop table' to delete all messages, or 'exit' to quit: ")
        if command.lower() == 'exit':
            break
        elif command.lower().startswith('delete '):
            try:
                message_id = int(command.split()[1])
                data = retrieve_message(message_id)
                if not data:
                    print("Invalid message ID!")
                else:
                    confirm = input("Are you sure you want to delete this message? (yes/no): ")
                    if confirm.lower() == 'yes' and verify_master_password(master_password):
                        from database import delete_message_by_id
                        delete_message_by_id(message_id)
                        print(f"Message ID {message_id} deleted successfully.")
                        if count_total_messages() == 0:
                            print("Empty Database!")
                    else:
                        print("Deletion canceled or incorrect master password.")
            except (IndexError, ValueError):
                print("Invalid command format. Use 'delete <ID>'.")
        elif command.lower() == 'drop table':
            confirm = input("Are you sure you want to delete all messages? (yes/no): ")
            if confirm.lower() == 'yes' and verify_master_password(master_password):
                from database import drop_database_table
                drop_database_table()
                print("All messages deleted successfully.")
                print("Empty Database!")
                setup_database()
            else:
                print("Deletion canceled or incorrect master password.")
        else:
            try:
                message_id = int(command)
                data = retrieve_message(message_id)
                if not data:
                    print("Invalid message ID!")
                else:
                    password = getpass.getpass("Enter Password: ")
                    decrypt_data(int(message_id), password)
            except ValueError:
                print("Invalid command. Please enter a valid message ID or command.")


def main():
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
    master_password = config.get("admin", "master_password")
    print("Welcome Admin!")
    adminpass = getpass.getpass("Enter Master Password to Start the Server: ")
    if adminpass == master_password:
        setup_database()
        print("Server started. Waiting for messages...")
        message_thread = threading.Thread(target=handle_new_messages, daemon=True)
        message_thread.start()
        prompt_thread = threading.Thread(target=prompt_user_for_decryption, daemon=True)
        prompt_thread.start()
        prompt_thread.join() 
    else:
        print("Login Failed")
if __name__ == "__main__":
    main()
