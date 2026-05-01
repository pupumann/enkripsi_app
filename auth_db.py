# auth_db.py
import mysql.connector, bcrypt, json, secrets, base64
from crypto import wrap_user_key, unwrap_user_key

def load_config():
    return json.load(open("config.json"))

class AuthDB:
    def __init__(self):
        cfg = load_config()['mysql']
        self.conn = mysql.connector.connect(
            host=cfg['host'],
            user=cfg['user'],
            password=cfg['password'],
            port=cfg['port']
        )
        self.cursor = self.conn.cursor(buffered=True)
        self._ensure_db()

    def _ensure_db(self):
        self.cursor.execute("CREATE DATABASE IF NOT EXISTS enkripsi_app")
        self.cursor.execute("USE enkripsi_app")
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE,
            password_hash VARBINARY(255),
            wrapped_key BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        self.conn.commit()

    def register_user(self, username, password):
        self.cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
        if self.cursor.fetchone(): return None

        user_key = secrets.token_bytes(32)
        wrapped = wrap_user_key(user_key, password)
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.cursor.execute("INSERT INTO users (username,password_hash,wrapped_key) VALUES (%s,%s,%s)",
                            (username, pw_hash, wrapped))
        self.conn.commit()
        return base64.b64encode(user_key).decode()

    def login_user(self, username, password):
        self.cursor.execute("SELECT id, password_hash, wrapped_key FROM users WHERE username=%s", (username,))
        row = self.cursor.fetchone()

        if not row:
            return None

        pw_hash = row[1]
        wrapped = row[2]

        # bcrypt compare → both must be bytes
        if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
            return None

        return {
            "id": row[0],
            "username": username,
            "wrapped_key": wrapped
        }
