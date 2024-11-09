import sqlite3
from datetime import datetime
def setup_database():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        user_id BLOB,
        message BLOB,
        username_iv BLOB,
        message_iv BLOB,
        username_salt BLOB,
        message_salt BLOB,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()


def store_message(user_id, message, iv_user, iv_message, salt_user, salt_message):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO messages (user_id, message, username_iv, message_iv, username_salt, message_salt, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, message, iv_user, iv_message, salt_user, salt_message, datetime.now()))
    conn.commit()
    conn.close()

def fetch_messages():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages")
    rows = cursor.fetchall()
    conn.close()
    print("\nID | Encrypted Username | Encrypted Message | Timestamp")
    print("-" * 50)
    for row in rows:
        print(f"{row[0]} | {row[1]} | {row[2]} | {row[5]}")


def retrieve_message(message_id):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, message, username_iv, message_iv, username_salt, message_salt FROM messages WHERE id = ?", (message_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None

#----------------------------------------------Later updated
def fetch_all_messages():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages")
    rows = cursor.fetchall()
    conn.close()
    return rows

def count_total_messages():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM messages")
    count = cursor.fetchone()[0]
    conn.close()
    return count

#-------------------------------------------------------------added later
def delete_message_by_id(message_id):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    conn.commit()
    conn.close()

def drop_database_table():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS messages")
    conn.commit()
    conn.close()
