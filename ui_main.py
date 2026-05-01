import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

from auth_db import AuthDB
from db_ops import DBOps


# ================= LOGIN =================
class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.auth = AuthDB()
        self.setWindowTitle("🔐 Secure DB Encryptor")
        self.resize(400, 300)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 Secure DB Encryptor")
        title.setFont(QFont("Arial", 14))
        title.setAlignment(Qt.AlignCenter)

        self.u = QLineEdit()
        self.u.setPlaceholderText("Username")

        self.p = QLineEdit()
        self.p.setPlaceholderText("Password")
        self.p.setEchoMode(QLineEdit.Password)

        btn_login = QPushButton("Login")
        btn_reg = QPushButton("Register")

        layout.addWidget(title)
        layout.addWidget(self.u)
        layout.addWidget(self.p)
        layout.addWidget(btn_login)
        layout.addWidget(btn_reg)

        self.setLayout(layout)

        btn_login.clicked.connect(self.do_login)
        btn_reg.clicked.connect(self.register)

    # ✅ FIX: masuk class
    def register(self):
        username = self.u.text().strip()
        password = self.p.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Username dan Password wajib diisi")
            return

        key = self.auth.register_user(username, password)
        if not key:
            QMessageBox.warning(self, "Error", "Username sudah ada")
            return

        # ================= POPUP =================
        dialog = QDialog(self)
        dialog.setWindowTitle("🔑 Simpan Key Anda")
        dialog.resize(400, 200)

        layout = QVBoxLayout(dialog)

        label = QLabel("Copy atau simpan key berikut:")
        label.setAlignment(Qt.AlignCenter)

        key_box = QLineEdit(key)
        key_box.setReadOnly(True)

        btn_copy = QPushButton("📋 Copy")
        btn_save = QPushButton("💾 Download TXT")
        btn_close = QPushButton("Tutup")

        btn_copy.setStyleSheet("background:#3498db; color:white;")
        btn_save.setStyleSheet("background:#2ecc71; color:white;")

        # FUNCTION
        def copy_key():
            QApplication.clipboard().setText(key)
            QMessageBox.information(dialog, "Sukses", "Key berhasil disalin")

        def save_key():
            file, _ = QFileDialog.getSaveFileName(
                dialog, "Simpan Key", "db_key.txt", "Text File (*.txt)"
            )
            if file:
                with open(file, "w") as f:
                    f.write(key)
                QMessageBox.information(dialog, "Sukses", "Key berhasil disimpan")

        btn_copy.clicked.connect(copy_key)
        btn_save.clicked.connect(save_key)
        btn_close.clicked.connect(dialog.close)

        # LAYOUT
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_copy)
        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_close)

        layout.addWidget(label)
        layout.addWidget(key_box)
        layout.addLayout(btn_layout)

        dialog.exec_()

    # ✅ FIX: tidak lagi di dalam register
    def do_login(self):
        user = self.auth.login_user(self.u.text(), self.p.text())
        if user:
            user["password"] = self.p.text()
            self.main = MainWindow(user)
            self.main.show()
            self.close()
        else:
            QMessageBox.warning(self, "Error", "Login gagal")


# ================= MAIN WINDOW =================
class MainWindow(QMainWindow):
    def __init__(self, user):
        super().__init__()
        self.user = user
        self.db = DBOps()

        self.setWindowTitle("Secure DB Encryptor")
        self.resize(1100, 600)

        self.init_ui()

    def log(self, text):
        from datetime import datetime
        time = datetime.now().strftime("%H:%M:%S")
        self.log_box.append(f"[{time}] {text}")

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)

        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("background:#2c3e50; color:white;")

        sb_layout = QVBoxLayout(sidebar)

        btn_home = QPushButton("🏠 Dashboard")
        btn_db = QPushButton("🗄 Database")

        for b in [btn_home, btn_db]:
            b.setStyleSheet("padding:10px; text-align:left;")
            sb_layout.addWidget(b)

        sb_layout.addStretch()

        self.stack = QStackedWidget()
        self.page_home = self.build_home()
        self.page_db = self.build_db_page()
        

        self.stack.addWidget(self.page_home)
        self.stack.addWidget(self.page_db)

        btn_home.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        btn_db.clicked.connect(lambda: self.stack.setCurrentIndex(1))

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.stack)

    def build_home(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        label = QLabel(f"👋 Selamat datang, {self.user['username']}")
        label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(label)

        return w

    def build_db_page(self):
        w = QWidget()
        layout = QHBoxLayout(w)

        left = QVBoxLayout()
        

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Host (contoh: localhost)")

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("User")

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.Password)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (3306)")

        btn_connect = QPushButton("🔌 Connect Database")
        self.combo_db = QComboBox()
        self.combo_db.addItems(self.db.list_databases())

        self.list_tbl = QListWidget()

        btn_refresh = QPushButton("Refresh")
        btn_encrypt = QPushButton("Encrypt")
        btn_decrypt = QPushButton("Decrypt")

        self.status = QLabel("Status: Idle")
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)

        left.addWidget(QLabel("Database"))
        left.addWidget(self.combo_db)
        left.addWidget(QLabel("Tabel"))
        left.addWidget(self.list_tbl)
        left.addWidget(btn_refresh)
        left.addWidget(btn_encrypt)
        left.addWidget(btn_decrypt)
        left.addWidget(self.status)
        left.addWidget(QLabel("Log Aktivitas"))
        left.addWidget(self.log_box)
        left.addWidget(QLabel("Koneksi Database"))
        left.addWidget(self.host_input)
        left.addWidget(self.user_input)
        left.addWidget(self.pass_input)
        left.addWidget(self.port_input)
        left.addWidget(btn_connect)

        self.table = QTableWidget()

        layout.addLayout(left, 2)
        layout.addWidget(self.table, 5)

        self.combo_db.currentIndexChanged.connect(self.load_tables)
        btn_refresh.clicked.connect(self.load_tables)
        self.list_tbl.itemClicked.connect(self.preview_table)

        btn_encrypt.clicked.connect(self.do_encrypt)
        btn_decrypt.clicked.connect(self.do_decrypt)
        btn_connect.clicked.connect(self.connect_db)

        self.load_tables()
        return w

    def load_tables(self):
        db = self.combo_db.currentText()

        if not db:
            return

        try:
            self.list_tbl.clear()
            self.list_tbl.addItems(self.db.list_tables(db))
        except Exception as e:
            self.log(f"ERROR load_tables: {e}")

    def preview_table(self):
        item = self.list_tbl.currentItem()
        if not item:
            return

        table = item.text()
        db = self.combo_db.currentText()
        rows = self.db.preview(db, table)

        if not rows:
            return

        self.table.setRowCount(len(rows))
        self.table.setColumnCount(len(rows[0]))

        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                self.table.setItem(r, c, QTableWidgetItem(str(val)))

    def request_key(self):
        key, ok = QInputDialog.getText(self, "Key", "Masukkan key:")
        return key if ok and key else None

    def do_encrypt(self):
        item = self.list_tbl.currentItem()
        if not item:
            return

        key = self.request_key()
        if not key:
            return

        db = self.combo_db.currentText()
        table = item.text()

        self.log(f"Mulai enkripsi: {db}.{table}")
        self.status.setText("Encrypting...")

        result = self.db.encrypt_table(db, table, key.encode())

        self.log(result["msg"])
        self.status.setText("Selesai")

        QMessageBox.information(self, "Info", result["msg"])
        self.preview_table()

    def do_decrypt(self):
        item = self.list_tbl.currentItem()
        if not item:
            return

        key = self.request_key()
        if not key:
            return

        db = self.combo_db.currentText()
        table = item.text()

        self.log(f"Mulai dekripsi: {db}.{table}")
        self.status.setText("Decrypting...")

        result = self.db.decrypt_table(db, table, key.encode())

        self.log(result["msg"])
        self.status.setText("Selesai")

        QMessageBox.information(self, "Info", result["msg"])
        self.preview_table()

    def connect_db(self):
        host = self.host_input.text().strip()
        user = self.user_input.text().strip()
        password = self.pass_input.text().strip()
        port = self.port_input.text().strip()

        if not host or not user:
            QMessageBox.warning(self, "Error", "Host dan User wajib diisi")
            return

        try:
            import mysql.connector

            self.db.conn = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                port=int(port) if port else 3306
            )

            self.db.cursor = self.db.conn.cursor(buffered=True)

            # refresh database list
            self.combo_db.clear()
            self.combo_db.addItems(self.db.list_databases())

            self.log(f"Berhasil connect ke {host}")
            QMessageBox.information(self, "Sukses", "Koneksi berhasil")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


# ================= RUN =================
def show_login():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    app.setStyle("Fusion")

    app.setStyleSheet("""
QMainWindow {
    background: #ecf0f1;
}

QLabel {
    font-size: 11pt;
}

QPushButton {
    background: #34495e;
    color: white;
    border-radius: 6px;
    padding: 8px;
    font-weight: bold;
}

QPushButton:hover {
    background: #1abc9c;
}

QComboBox, QListWidget {
    padding: 5px;
    border-radius: 4px;
}

QTableWidget {
    background: white;
    gridline-color: #bdc3c7;
}

QTextEdit {
    background: #1e1e1e;
    color: #00ff9c;
    font-family: Consolas;
}
""")

    w = LoginWindow()
    w.show()
    app.exec_()


if __name__ == "__main__":
    show_login()