# db_ops.py
import mysql.connector
from crypto import xor_encrypt, xor_decrypt

TEXT_TYPES = {"varchar","char","text","tinytext","mediumtext","longtext"}


class DBOps:
    def __init__(self):
        self.conn = None
        self.cursor = None

    # ================= CONNECT =================
    def connect(self, host, user, password, port=3306):
        try:
            self.conn = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                port=port
            )
            self.cursor = self.conn.cursor(buffered=True)
            return True
        except Exception as e:
            print("ERROR connect:", e)
            return False

    def is_connected(self):
        return self.conn is not None

    # ================= DATABASE =================
    def list_databases(self):
        if not self.conn:
            return []

        try:
            self.cursor.execute("SHOW DATABASES")
            return [r[0] for r in self.cursor.fetchall()]
        except Exception as e:
            print("ERROR list_databases:", e)
            return []

    def list_tables(self, db):
        if not self.conn or not db:
            return []

        try:
            self.cursor.execute(f"USE `{db}`")
            self.cursor.execute("SHOW TABLES")
            return [r[0] for r in self.cursor.fetchall()]
        except Exception as e:
            print("ERROR list_tables:", e)
            return []

    def preview(self, db_name, table):
        if not self.conn:
            return []

        try:
            self.cursor.execute(f"USE `{db_name}`")
            self.cursor.execute(f"SELECT * FROM `{table}` LIMIT 50")
            return self.cursor.fetchall()
        except Exception as e:
            print(f"[ERROR preview] {e}")
            return []

    def get_text_columns(self, db, table):
        if not self.conn:
            return []

        sql = """SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
                 WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s"""
        self.cursor.execute(sql, (db, table))
        return [r[0] for r in self.cursor.fetchall() if r[1].lower() in TEXT_TYPES]

    # ================= ENCRYPT =================
    def encrypt_table(self, db, table, key, cb=None):
        if not self.conn:
            return {"ok": False, "msg": "Belum terkoneksi ke database"}

        self.cursor.execute(f"USE `{db}`")

        text_cols = self.get_text_columns(db, table)
        if not text_cols:
            return {"ok": False, "msg": "Tidak ada kolom teks"}

        self.cursor.execute(f"SELECT * FROM `{table}`")
        rows = self.cursor.fetchall()
        headers = [desc[0] for desc in self.cursor.description]

        total = len(rows)

        for i, row in enumerate(rows, start=1):
            updates = []
            values = []

            for col in text_cols:
                idx = headers.index(col)

                # 🔴 SKIP PRIMARY KEY (kolom pertama)
                if idx == 0:
                    continue

                val = row[idx]

                if val:
                    try:
                        enc = xor_encrypt(str(val).encode(), key).hex()
                        updates.append(f"`{col}`=%s")
                        values.append(enc)
                    except Exception as e:
                        print("ERROR encrypt:", e)

            if updates:
                pk = headers[0]
                values.append(row[0])

                sql = f"UPDATE `{table}` SET {','.join(updates)} WHERE `{pk}`=%s"
                self.cursor.execute(sql, tuple(values))

            if cb:
                cb(i, total)

        self.conn.commit()
        return {"ok": True, "msg": f"Enkripsi {total} baris selesai"}

    # ================= DECRYPT =================
    def decrypt_table(self, db, table, key, cb=None):
        import re

        def is_hex(s):
            return isinstance(s, str) and re.fullmatch(r'[0-9a-fA-F]+', s)

        if not self.conn:
            return {"ok": False, "msg": "Belum terkoneksi ke database"}

        self.cursor.execute(f"USE `{db}`")

        text_cols = self.get_text_columns(db, table)
        if not text_cols:
            return {"ok": False, "msg": "Tidak ada kolom teks"}

        self.cursor.execute(f"SELECT * FROM `{table}`")
        rows = self.cursor.fetchall()
        headers = [desc[0] for desc in self.cursor.description]

        total = len(rows)

        for i, row in enumerate(rows, start=1):
            updates = []
            values = []

            for col in text_cols:
                idx = headers.index(col)

                # 🔴 SKIP PRIMARY KEY
                if idx == 0:
                    continue

                val = row[idx]

                if val and is_hex(val):
                    try:
                        dec = xor_decrypt(bytes.fromhex(val), key).decode(errors='replace')
                        updates.append(f"`{col}`=%s")
                        values.append(dec)
                    except Exception as e:
                        print("ERROR decrypt:", e)

            if updates:
                pk = headers[0]
                values.append(row[0])

                sql = f"UPDATE `{table}` SET {','.join(updates)} WHERE `{pk}`=%s"
                self.cursor.execute(sql, tuple(values))

            if cb:
                cb(i, total)

        self.conn.commit()
        return {"ok": True, "msg": f"Dekripsi {total} baris selesai"}