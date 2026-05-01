# data_db.py
import json
import mysql.connector
from crypto import xor_encrypt_bytes, xor_decrypt_bytes

CONFIG_PATH = "config.json"

def load_config():
    return json.load(open(CONFIG_PATH, "r"))

class DataDB:
    def __init__(self):
        cfg = load_config()['mysql']
        self.conn = mysql.connector.connect(
            host=cfg['host'],
            user=cfg['user'],
            password=cfg['password'],
            database=cfg['database'],
            port=cfg.get('port', 3306)
        )
        self.cursor = self.conn.cursor(buffered=True)

    def insert_data_for_user(self, user_id: int, nama: str, plaintext: str, user_key: bytes):
        # encrypt plaintext (string -> bytes)
        cipher = xor_encrypt_bytes(plaintext.encode(), user_key)
        sql = "INSERT INTO data_enkripsi (user_id, nama, data_enkripsi) VALUES (%s, %s, %s)"
        self.cursor.execute(sql, (user_id, nama, cipher))
        self.conn.commit()

    def fetch_data_for_user(self, user_id: int, user_key: bytes):
        sql = "SELECT id, nama, data_enkripsi, created_at FROM data_enkripsi WHERE user_id=%s ORDER BY created_at DESC"
        self.cursor.execute(sql, (user_id,))
        out = []
        for (did, nama, enc, created_at) in self.cursor.fetchall():
            try:
                dec = xor_decrypt_bytes(enc, user_key).decode(errors='replace')
            except Exception:
                dec = "[DECRYPT_FAILED]"
            out.append({"id": did, "nama": nama, "data": dec, "created_at": created_at})
        return out

    def delete_data(self, data_id: int, user_id: int):
        sql = "DELETE FROM data_enkripsi WHERE id=%s AND user_id=%s"
        self.cursor.execute(sql, (data_id, user_id))
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()
