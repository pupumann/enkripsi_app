"""
XOR Encryption Tool - Database Encryption/Decryption
Implementasi Algoritma XOR Termodifikasi dengan Dynamic Key (LCG) dan Transformasi Non-Linear
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import mysql.connector
import secrets
import string
import json
import os
import pyperclip
from pathlib import Path
from datetime import datetime
import threading


# ─────────────────────────────────────────────────────────────────────────────
# ALGORITMA ENKRIPSI XOR TERMODIFIKASI
# ─────────────────────────────────────────────────────────────────────────────

class XORCipher:
    """
    Algoritma XOR termodifikasi dengan:
    1. Dynamic Key Generation (LCG - Linear Congruential Generator)
    2. Transformasi Non-Linear berbasis fungsi polinomial
    
    LCG: K(i+1) = (a * K(i) + c) mod m
    Enkripsi: C(i) = (P(i) XOR K(i)) + T(i)  mod 256
    Dekripsi: P(i) = (C(i) - T(i)) mod 256 XOR K(i)
    T(i) = transformasi non-linear dari K(i)
    """

    # Konstanta LCG (Numerical Recipes)
    LCG_A = 1664525
    LCG_C = 1013904223
    LCG_M = 2**32

    @staticmethod
    def _lcg_next(k: int) -> int:
        return (XORCipher.LCG_A * k + XORCipher.LCG_C) % XORCipher.LCG_M

    @staticmethod
    def _nonlinear(k: int) -> int:
        """Transformasi non-linear: f(k) = (k^2 + k*3 + 7) mod 256"""
        return (k * k + k * 3 + 7) % 256

    @classmethod
    def _derive_seed(cls, key_str: str) -> int:
        """Derive integer seed from key string."""
        seed = 0
        for ch in key_str:
            seed = (seed * 31 + ord(ch)) % cls.LCG_M
        return seed if seed != 0 else 0xDEADBEEF

    @classmethod
    def encrypt(cls, plaintext: str, key: str) -> str:
        """Enkripsi string, return hex string."""
        if not plaintext:
            return plaintext
        k = cls._derive_seed(key)
        result = []
        for ch in plaintext:
            k = cls._lcg_next(k)
            ki = k & 0xFF
            t = cls._nonlinear(ki)
            ci = ((ord(ch) ^ ki) + t) % 256
            result.append(f"{ci:02x}")
        return "".join(result)

    @classmethod
    def decrypt(cls, ciphertext_hex: str, key: str) -> str:
        """Dekripsi hex string, return plaintext."""
        if not ciphertext_hex:
            return ciphertext_hex
        try:
            k = cls._derive_seed(key)
            result = []
            # Split hex string into pairs
            for i in range(0, len(ciphertext_hex), 2):
                ci = int(ciphertext_hex[i:i+2], 16)
                k = cls._lcg_next(k)
                ki = k & 0xFF
                t = cls._nonlinear(ki)
                pi = ((ci - t) % 256) ^ ki
                result.append(chr(pi))
            return "".join(result)
        except Exception:
            return "[DECRYPT ERROR]"

    @classmethod
    def is_encrypted(cls, value: str) -> bool:
        """Heuristic: check if value looks like hex ciphertext."""
        if not value or len(value) % 2 != 0:
            return False
        return all(c in "0123456789abcdefABCDEF" for c in value)


# ─────────────────────────────────────────────────────────────────────────────
# KEY MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class KeyManager:
    KEY_FILE = Path.home() / ".enc_tool_key.json"

    @staticmethod
    def generate_key(length: int = 64) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def save_key(key: str, username: str):
        data = {"username": username, "key": key, "created_at": datetime.now().isoformat()}
        with open(KeyManager.KEY_FILE, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load_key() -> dict | None:
        if KeyManager.KEY_FILE.exists():
            with open(KeyManager.KEY_FILE) as f:
                return json.load(f)
        return None

    @staticmethod
    def key_exists() -> bool:
        return KeyManager.KEY_FILE.exists()


# ─────────────────────────────────────────────────────────────────────────────
# THEME
# ─────────────────────────────────────────────────────────────────────────────

DARK_BG     = "#0D1117"
PANEL_BG    = "#161B22"
BORDER_COL  = "#30363D"
ACCENT      = "#58A6FF"
ACCENT2     = "#3FB950"
WARN        = "#F85149"
TEXT_PRI    = "#E6EDF3"
TEXT_SEC    = "#8B949E"
ENTRY_BG    = "#21262D"
BTN_ENC     = "#238636"
BTN_DEC     = "#1F6FEB"
BTN_HOV_ENC = "#2EA043"
BTN_HOV_DEC = "#388BFD"


def apply_theme(root):
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=DARK_BG, foreground=TEXT_PRI, font=("Segoe UI", 10))
    style.configure("TFrame", background=DARK_BG)
    style.configure("TLabel", background=DARK_BG, foreground=TEXT_PRI)
    style.configure("TLabelframe", background=PANEL_BG, foreground=ACCENT, relief="flat",
                    bordercolor=BORDER_COL)
    style.configure("TLabelframe.Label", background=PANEL_BG, foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"))
    style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=TEXT_PRI,
                    insertcolor=TEXT_PRI, relief="flat", bordercolor=BORDER_COL)
    style.configure("TCombobox", fieldbackground=ENTRY_BG, foreground=TEXT_PRI,
                    background=ENTRY_BG, arrowcolor=TEXT_SEC)
    style.map("TCombobox", fieldbackground=[("readonly", ENTRY_BG)])
    style.configure("Treeview", background=PANEL_BG, foreground=TEXT_PRI,
                    fieldbackground=PANEL_BG, rowheight=26, font=("Segoe UI", 9))
    style.configure("Treeview.Heading", background=ENTRY_BG, foreground=ACCENT,
                    relief="flat", font=("Segoe UI", 9, "bold"))
    style.map("Treeview", background=[("selected", "#1F6FEB")])
    style.configure("TScrollbar", background=PANEL_BG, troughcolor=DARK_BG,
                    arrowcolor=TEXT_SEC)
    style.configure("TNotebook", background=DARK_BG, tabmargins=[2, 5, 2, 0])
    style.configure("TNotebook.Tab", background=PANEL_BG, foreground=TEXT_SEC,
                    padding=[16, 6])
    style.map("TNotebook.Tab",
              background=[("selected", DARK_BG)],
              foreground=[("selected", ACCENT)])


def make_button(parent, text, command, color=BTN_ENC, hover=BTN_HOV_ENC, width=None):
    btn = tk.Button(parent, text=text, command=command,
                    bg=color, fg="white", relief="flat", cursor="hand2",
                    font=("Segoe UI", 9, "bold"), activebackground=hover,
                    activeforeground="white", padx=12, pady=6, bd=0)
    if width:
        btn.config(width=width)
    btn.bind("<Enter>", lambda e: btn.config(bg=hover))
    btn.bind("<Leave>", lambda e: btn.config(bg=color))
    return btn


# ─────────────────────────────────────────────────────────────────────────────
# REGISTER SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class RegisterScreen(tk.Toplevel):
    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.on_success = on_success
        self.title("Register — Buat Akun & Key Enkripsi")
        self.geometry("520x480")
        self.configure(bg=DARK_BG)
        self.resizable(False, False)
        self._generated_key = None
        self._build()
        self.grab_set()

    def _build(self):
        # Header
        tk.Label(self, text="🔐 SETUP ENKRIPSI", font=("Segoe UI", 18, "bold"),
                 bg=DARK_BG, fg=ACCENT).pack(pady=(30, 4))
        tk.Label(self, text="Buat akun dan generate key enkripsi Anda",
                 font=("Segoe UI", 10), bg=DARK_BG, fg=TEXT_SEC).pack(pady=(0, 24))

        form = tk.Frame(self, bg=DARK_BG)
        form.pack(fill="x", padx=48)

        # Username
        tk.Label(form, text="Username", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(anchor="w")
        self.username_var = tk.StringVar()
        e = tk.Entry(form, textvariable=self.username_var, bg=ENTRY_BG, fg=TEXT_PRI,
                     relief="flat", font=("Segoe UI", 10), insertbackground=TEXT_PRI,
                     highlightthickness=1, highlightbackground=BORDER_COL,
                     highlightcolor=ACCENT)
        e.pack(fill="x", pady=(2, 16), ipady=8)

        # Generate Key button
        gen_btn = make_button(form, "⚡ Generate Key Enkripsi", self._generate_key,
                              color="#6E40C9", hover="#8957E5")
        gen_btn.pack(fill="x", pady=(0, 12))

        # Key display
        tk.Label(form, text="Key Enkripsi (hanya ditampilkan sekali!)",
                 bg=DARK_BG, fg=WARN, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        key_frame = tk.Frame(form, bg=ENTRY_BG, highlightthickness=1,
                             highlightbackground=BORDER_COL)
        key_frame.pack(fill="x", pady=(2, 4))
        self.key_text = tk.Text(key_frame, height=3, bg=ENTRY_BG, fg=ACCENT2,
                                font=("Consolas", 9), relief="flat", wrap="word",
                                state="disabled", insertbackground=TEXT_PRI)
        self.key_text.pack(fill="x", padx=8, pady=8)

        tk.Label(form, text="⚠  Simpan key ini! Key tidak bisa diregenerasi.",
                 bg=DARK_BG, fg=WARN, font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 16))

        # Action buttons
        btn_row = tk.Frame(form, bg=DARK_BG)
        btn_row.pack(fill="x")
        make_button(btn_row, "📋 Salin Key", self._copy_key,
                    color="#6E40C9", hover="#8957E5").pack(side="left", padx=(0, 8))
        make_button(btn_row, "💾 Download TXT", self._download_key,
                    color="#7D4E00", hover="#9B6100").pack(side="left")
        make_button(btn_row, "✅ Selesai & Login", self._finish,
                    color=BTN_ENC, hover=BTN_HOV_ENC).pack(side="right")

    def _generate_key(self):
        username = self.username_var.get().strip()
        if not username:
            messagebox.showwarning("Username kosong", "Masukkan username terlebih dahulu.",
                                   parent=self)
            return
        self._generated_key = KeyManager.generate_key(64)
        self.key_text.config(state="normal")
        self.key_text.delete("1.0", "end")
        self.key_text.insert("1.0", self._generated_key)
        self.key_text.config(state="disabled")

    def _copy_key(self):
        if not self._generated_key:
            messagebox.showwarning("Belum ada key", "Generate key dulu!", parent=self)
            return
        try:
            pyperclip.copy(self._generated_key)
            messagebox.showinfo("Disalin", "Key berhasil disalin ke clipboard.", parent=self)
        except Exception:
            messagebox.showinfo("Key", self._generated_key, parent=self)

    def _download_key(self):
        if not self._generated_key:
            messagebox.showwarning("Belum ada key", "Generate key dulu!", parent=self)
            return
        username = self.username_var.get().strip() or "user"
        filename = f"enc_key_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = Path.home() / "Downloads" / filename
        path.parent.mkdir(exist_ok=True)
        with open(path, "w") as f:
            f.write(f"XOR Encryption Key\n")
            f.write(f"Username: {username}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"{'='*60}\n")
            f.write(self._generated_key)
        messagebox.showinfo("Disimpan", f"Key disimpan di:\n{path}", parent=self)

    def _finish(self):
        if not self._generated_key:
            messagebox.showwarning("Belum ada key", "Generate key dulu!", parent=self)
            return
        username = self.username_var.get().strip()
        if not username:
            messagebox.showwarning("Username kosong", "Masukkan username.", parent=self)
            return
        KeyManager.save_key(self._generated_key, username)
        self.destroy()
        self.on_success(username, self._generated_key)


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class LoginScreen(tk.Toplevel):
    def __init__(self, parent, on_success, on_register):
        super().__init__(parent)
        self.on_success = on_success
        self.on_register = on_register
        self.title("Login — XOR Encryption Tool")
        self.geometry("460x400")
        self.configure(bg=DARK_BG)
        self.resizable(False, False)
        self._build()
        self.grab_set()

    def _build(self):
        tk.Label(self, text="🔐 XOR ENC TOOL", font=("Segoe UI", 20, "bold"),
                 bg=DARK_BG, fg=ACCENT).pack(pady=(40, 4))
        tk.Label(self, text="Database Encryption Dashboard",
                 font=("Segoe UI", 10), bg=DARK_BG, fg=TEXT_SEC).pack(pady=(0, 32))

        form = tk.Frame(self, bg=DARK_BG)
        form.pack(fill="x", padx=60)

        # Username
        tk.Label(form, text="Username", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(anchor="w")
        self.username_var = tk.StringVar()
        tk.Entry(form, textvariable=self.username_var, bg=ENTRY_BG, fg=TEXT_PRI,
                 relief="flat", font=("Segoe UI", 10), insertbackground=TEXT_PRI,
                 highlightthickness=1, highlightbackground=BORDER_COL,
                 highlightcolor=ACCENT).pack(fill="x", pady=(2, 16), ipady=8)

        # Key
        tk.Label(form, text="Key Enkripsi", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(anchor="w")
        self.key_var = tk.StringVar()
        tk.Entry(form, textvariable=self.key_var, bg=ENTRY_BG, fg=TEXT_PRI,
                 show="•", relief="flat", font=("Segoe UI", 10),
                 insertbackground=TEXT_PRI, highlightthickness=1,
                 highlightbackground=BORDER_COL, highlightcolor=ACCENT
                 ).pack(fill="x", pady=(2, 24), ipady=8)

        make_button(form, "  Login →", self._login, width=30).pack(fill="x", ipady=2)

        tk.Label(self, text="Belum punya akun?", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(pady=(16, 2))
        reg_lbl = tk.Label(self, text="Daftar di sini", bg=DARK_BG, fg=ACCENT,
                           font=("Segoe UI", 9, "underline"), cursor="hand2")
        reg_lbl.pack()
        reg_lbl.bind("<Button-1>", lambda e: [self.destroy(), self.on_register()])

    def _login(self):
        username = self.username_var.get().strip()
        key = self.key_var.get().strip()
        if not username or not key:
            messagebox.showwarning("Input kosong", "Username dan key harus diisi.", parent=self)
            return
        saved = KeyManager.load_key()
        if not saved:
            messagebox.showerror("Akun tidak ditemukan",
                                 "Belum ada akun terdaftar. Silakan daftar dulu.", parent=self)
            return
        if saved["username"] == username and saved["key"] == key:
            self.destroy()
            self.on_success(username, key)
        else:
            messagebox.showerror("Login gagal", "Username atau key salah.", parent=self)


# ─────────────────────────────────────────────────────────────────────────────
# DB CONNECTION DIALOG
# ─────────────────────────────────────────────────────────────────────────────

class DBConnectDialog(tk.Toplevel):
    def __init__(self, parent, on_connect):
        super().__init__(parent)
        self.on_connect = on_connect
        self.title("Koneksi Database")
        self.geometry("420x500")
        self.configure(bg=DARK_BG)
        self.resizable(False, False)
        self._build()
        self.grab_set()

    def _build(self):
        tk.Label(self, text="🗄  Koneksi MySQL", font=("Segoe UI", 14, "bold"),
                 bg=DARK_BG, fg=ACCENT).pack(pady=(24, 20))

        form = tk.Frame(self, bg=DARK_BG)
        form.pack(fill="x", padx=40)

        fields = [
            ("Host", "host_var", "localhost"),
            ("Port", "port_var", "3306"),
            ("Username DB", "user_var", "root"),
            ("Password DB", "pass_var", ""),
            ("Database", "db_var", ""),
        ]
        for label, attr, default in fields:
            tk.Label(form, text=label, bg=DARK_BG, fg=TEXT_SEC,
                     font=("Segoe UI", 9)).pack(anchor="w")
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            show = "•" if "pass" in attr else ""
            tk.Entry(form, textvariable=var, show=show, bg=ENTRY_BG, fg=TEXT_PRI,
                     relief="flat", font=("Segoe UI", 10), insertbackground=TEXT_PRI,
                     highlightthickness=1, highlightbackground=BORDER_COL,
                     highlightcolor=ACCENT).pack(fill="x", pady=(2, 10), ipady=6)

        make_button(form, "🔗 Connect", self._connect).pack(fill="x", ipady=2)

    def _connect(self):
        try:
            conn = mysql.connector.connect(
                host=self.host_var.get(),
                port=int(self.port_var.get()),
                user=self.user_var.get(),
                password=self.pass_var.get(),
                database=self.db_var.get() or None
            )
            self.destroy()
            self.on_connect(conn, self.db_var.get())
        except Exception as ex:
            messagebox.showerror("Koneksi gagal", str(ex), parent=self)


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

class Dashboard(tk.Frame):
    def __init__(self, master, username, key):
        super().__init__(master, bg=DARK_BG)
        self.master = master
        self.username = username
        self.key = key
        self.db_conn = None
        self.current_db = None
        self.selected_table = None
        self.pack(fill="both", expand=True)
        self._build_layout()

    # ── LAYOUT ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        # Top bar
        topbar = tk.Frame(self, bg=PANEL_BG, height=52)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        tk.Label(topbar, text="🔐 XOR ENC TOOL", font=("Segoe UI", 13, "bold"),
                 bg=PANEL_BG, fg=ACCENT).pack(side="left", padx=20, pady=12)
        tk.Label(topbar, text=f"👤 {self.username}", font=("Segoe UI", 9),
                 bg=PANEL_BG, fg=TEXT_SEC).pack(side="right", padx=20)

        # Separator
        tk.Frame(self, bg=BORDER_COL, height=1).pack(fill="x")

        # Content area
        content = tk.Frame(self, bg=DARK_BG)
        content.pack(fill="both", expand=True, padx=16, pady=12)

        # Left panel - DB & Tables
        left = tk.Frame(content, bg=PANEL_BG, width=220)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)
        self._build_left_panel(left)

        # Right panel
        right = tk.Frame(content, bg=DARK_BG)
        right.pack(side="left", fill="both", expand=True)
        self._build_right_panel(right)

        # Status bar
        self.status_var = tk.StringVar(value="Belum terhubung ke database.")
        status_bar = tk.Frame(self, bg=PANEL_BG, height=28)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        tk.Label(status_bar, textvariable=self.status_var, bg=PANEL_BG, fg=TEXT_SEC,
                 font=("Segoe UI", 8), anchor="w").pack(fill="x", padx=12, pady=6)

    def _build_left_panel(self, parent):
        tk.Label(parent, text="DATABASE", font=("Segoe UI", 9, "bold"),
                 bg=PANEL_BG, fg=TEXT_SEC).pack(anchor="w", padx=12, pady=(12, 6))

        make_button(parent, "🔗 Hubungkan DB", self._connect_db,
                    color="#6E40C9", hover="#8957E5").pack(fill="x", padx=12)

        tk.Frame(parent, bg=BORDER_COL, height=1).pack(fill="x", padx=12, pady=10)

        tk.Label(parent, text="TABEL", font=("Segoe UI", 9, "bold"),
                 bg=PANEL_BG, fg=TEXT_SEC).pack(anchor="w", padx=12, pady=(0, 6))

        # Table list
        list_frame = tk.Frame(parent, bg=PANEL_BG)
        list_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        scrollbar = tk.Scrollbar(list_frame, bg=PANEL_BG)
        scrollbar.pack(side="right", fill="y")

        self.table_listbox = tk.Listbox(
            list_frame, bg=ENTRY_BG, fg=TEXT_PRI, relief="flat",
            selectbackground=BTN_DEC, selectforeground="white",
            font=("Segoe UI", 9), yscrollcommand=scrollbar.set,
            activestyle="none", highlightthickness=0, bd=0
        )
        self.table_listbox.pack(fill="both", expand=True)
        scrollbar.config(command=self.table_listbox.yview)
        self.table_listbox.bind("<<ListboxSelect>>", self._on_table_select)

    def _build_right_panel(self, parent):
        # Action toolbar
        toolbar = tk.Frame(parent, bg=DARK_BG)
        toolbar.pack(fill="x", pady=(0, 10))

        tk.Label(toolbar, text="Tabel:", bg=DARK_BG, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        self.table_label = tk.Label(toolbar, text="—", bg=DARK_BG, fg=ACCENT,
                                    font=("Segoe UI", 9, "bold"))
        self.table_label.pack(side="left", padx=(0, 16))

        self.enc_btn = make_button(toolbar, "🔒 Enkripsi Tabel",
                                   self._encrypt_table, BTN_ENC, BTN_HOV_ENC)
        self.enc_btn.pack(side="left", padx=(0, 8))

        self.dec_btn = make_button(toolbar, "🔓 Dekripsi Tabel",
                                   self._decrypt_table, BTN_DEC, BTN_HOV_DEC)
        self.dec_btn.pack(side="left", padx=(0, 8))

        make_button(toolbar, "🔄 Refresh", self._refresh_preview,
                    color="#374151", hover="#4B5563").pack(side="left", padx=(0, 8))

        # Progress bar
        self.progress = ttk.Progressbar(toolbar, mode="indeterminate", length=120)
        self.progress.pack(side="right")

        # Preview area
        preview_frame = ttk.LabelFrame(parent, text=" Preview Tabel ", padding=8)
        preview_frame.pack(fill="both", expand=True)

        # Treeview with scrollbars
        tree_frame = tk.Frame(preview_frame, bg=PANEL_BG)
        tree_frame.pack(fill="both", expand=True)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        self.tree = ttk.Treeview(tree_frame, yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set, show="headings")
        self.tree.pack(fill="both", expand=True)
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Log area
        log_frame = ttk.LabelFrame(parent, text=" Log ", padding=6)
        log_frame.pack(fill="x", pady=(8, 0))

        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=5, bg=ENTRY_BG, fg=ACCENT2,
            font=("Consolas", 8), relief="flat", state="disabled",
            insertbackground=TEXT_PRI
        )
        self.log_text.pack(fill="x")

    # ── DB ACTIONS ─────────────────────────────────────────────────────────────

    def _connect_db(self):
        DBConnectDialog(self.master, self._on_db_connected)

    def _on_db_connected(self, conn, db_name):
        self.db_conn = conn
        self.current_db = db_name
        self._log(f"✅ Terhubung ke database: {db_name or 'N/A'}")
        self.set_status(f"Terhubung: {db_name or conn.server_host}")
        self._load_tables()

    def _load_tables(self):
        if not self.db_conn:
            return
        try:
            cursor = self.db_conn.cursor()
            if self.current_db:
                cursor.execute("SHOW TABLES")
            else:
                cursor.execute("SHOW DATABASES")
            tables = [row[0] for row in cursor.fetchall()]
            self.table_listbox.delete(0, "end")
            for t in tables:
                self.table_listbox.insert("end", f"  {t}")
            cursor.close()
            self._log(f"📋 {len(tables)} tabel ditemukan.")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _on_table_select(self, event):
        sel = self.table_listbox.curselection()
        if not sel:
            return
        name = self.table_listbox.get(sel[0]).strip()
        self.selected_table = name
        self.table_label.config(text=name)
        self._refresh_preview()

    def _refresh_preview(self):
        if not self.db_conn or not self.selected_table:
            return
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(f"SELECT * FROM `{self.selected_table}` LIMIT 50")
            rows = cursor.fetchall()
            cols = [desc[0] for desc in cursor.description]
            cursor.close()

            self.tree.delete(*self.tree.get_children())
            self.tree["columns"] = cols
            for c in cols:
                self.tree.heading(c, text=c)
                self.tree.column(c, width=120, minwidth=80)

            for row in rows:
                self.tree.insert("", "end", values=[str(v) if v is not None else "NULL" for v in row])

            self._log(f"🔍 Preview: {len(rows)} baris dari `{self.selected_table}`")
            self.set_status(f"Preview: {self.selected_table} ({len(rows)} baris)")
        except Exception as ex:
            messagebox.showerror("Error preview", str(ex))

    # ── ENCRYPT / DECRYPT ──────────────────────────────────────────────────────

    def _encrypt_table(self):
        if not self._check_ready():
            return
        confirm = messagebox.askyesno(
            "Konfirmasi Enkripsi",
            f"Enkripsi semua kolom teks di tabel '{self.selected_table}'?\n\n"
            "Pastikan Anda menyimpan key enkripsi sebelum melanjutkan!",
            parent=self.master
        )
        if confirm:
            threading.Thread(target=self._do_encrypt, daemon=True).start()

    def _decrypt_table(self):
        if not self._check_ready():
            return
        confirm = messagebox.askyesno(
            "Konfirmasi Dekripsi",
            f"Dekripsi semua kolom teks di tabel '{self.selected_table}'?\n\n"
            "Pastikan key enkripsi yang digunakan benar.",
            parent=self.master
        )
        if confirm:
            threading.Thread(target=self._do_decrypt, daemon=True).start()

    def _check_ready(self):
        if not self.db_conn:
            messagebox.showwarning("Belum terhubung", "Hubungkan ke database dulu!")
            return False
        if not self.selected_table:
            messagebox.showwarning("Pilih tabel", "Pilih tabel dari daftar.")
            return False
        return True

    def _get_text_columns(self, table):
        cursor = self.db_conn.cursor()
        cursor.execute(f"DESCRIBE `{table}`")
        cols = []
        for row in cursor.fetchall():
            col_name, col_type = row[0], row[1].lower()
            if any(t in col_type for t in ["char", "text", "varchar", "tinytext",
                                            "mediumtext", "longtext", "enum", "set"]):
                cols.append(col_name)
        cursor.close()
        return cols

    def _get_primary_key(self, table):
        cursor = self.db_conn.cursor()
        cursor.execute(f"SHOW KEYS FROM `{table}` WHERE Key_name = 'PRIMARY'")
        row = cursor.fetchone()
        cursor.close()
        return row[4] if row else None

    def _do_encrypt(self):
        self._start_progress()
        try:
            table = self.selected_table
            text_cols = self._get_text_columns(table)
            pk = self._get_primary_key(table)

            if not text_cols:
                self._log("⚠  Tidak ada kolom teks ditemukan.")
                return
            if not pk:
                self._log("⚠  Tidak ada primary key, tidak dapat update.")
                return

            cursor = self.db_conn.cursor()
            cursor.execute(f"SELECT `{pk}`, {', '.join(f'`{c}`' for c in text_cols)} FROM `{table}`")
            rows = cursor.fetchall()

            count = 0
            for row in rows:
                pk_val = row[0]
                updates = []
                vals = []
                for i, col in enumerate(text_cols):
                    val = row[i + 1]
                    if val is None:
                        continue
                    val_str = str(val)
                    if not XORCipher.is_encrypted(val_str):
                        encrypted = XORCipher.encrypt(val_str, self.key)
                        updates.append(f"`{col}` = %s")
                        vals.append(encrypted)
                if updates:
                    vals.append(pk_val)
                    cursor.execute(
                        f"UPDATE `{table}` SET {', '.join(updates)} WHERE `{pk}` = %s",
                        vals
                    )
                    count += 1

            self.db_conn.commit()
            cursor.close()
            self._log(f"🔒 Enkripsi selesai: {count} baris diproses di '{table}'")
            self.after(0, self._refresh_preview)
        except Exception as ex:
            self._log(f"❌ Error enkripsi: {ex}")
        finally:
            self._stop_progress()

    def _do_decrypt(self):
        self._start_progress()
        try:
            table = self.selected_table
            text_cols = self._get_text_columns(table)
            pk = self._get_primary_key(table)

            if not text_cols:
                self._log("⚠  Tidak ada kolom teks ditemukan.")
                return
            if not pk:
                self._log("⚠  Tidak ada primary key, tidak dapat update.")
                return

            cursor = self.db_conn.cursor()
            cursor.execute(f"SELECT `{pk}`, {', '.join(f'`{c}`' for c in text_cols)} FROM `{table}`")
            rows = cursor.fetchall()

            count = 0
            for row in rows:
                pk_val = row[0]
                updates = []
                vals = []
                for i, col in enumerate(text_cols):
                    val = row[i + 1]
                    if val is None:
                        continue
                    val_str = str(val)
                    if XORCipher.is_encrypted(val_str):
                        decrypted = XORCipher.decrypt(val_str, self.key)
                        updates.append(f"`{col}` = %s")
                        vals.append(decrypted)
                if updates:
                    vals.append(pk_val)
                    cursor.execute(
                        f"UPDATE `{table}` SET {', '.join(updates)} WHERE `{pk}` = %s",
                        vals
                    )
                    count += 1

            self.db_conn.commit()
            cursor.close()
            self._log(f"🔓 Dekripsi selesai: {count} baris diproses di '{table}'")
            self.after(0, self._refresh_preview)
        except Exception as ex:
            self._log(f"❌ Error dekripsi: {ex}")
        finally:
            self._stop_progress()

    # ── HELPERS ────────────────────────────────────────────────────────────────

    def _log(self, msg):
        def _do():
            self.log_text.config(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert("end", f"[{ts}] {msg}\n")
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        self.after(0, _do)

    def set_status(self, msg):
        self.after(0, lambda: self.status_var.set(msg))

    def _start_progress(self):
        self.after(0, self.progress.start)

    def _stop_progress(self):
        self.after(0, self.progress.stop)


# ─────────────────────────────────────────────────────────────────────────────
# APP CONTROLLER
# ─────────────────────────────────────────────────────────────────────────────

class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("XOR Encryption Tool")
        self.root.geometry("1000x680")
        self.root.configure(bg=DARK_BG)
        self.root.minsize(800, 560)
        apply_theme(self.root)
        self._start()
        self.root.mainloop()

    def _start(self):
        # Hide main window until login
        self.root.withdraw()
        if KeyManager.key_exists():
            self._show_login()
        else:
            self._show_register()

    def _show_register(self):
        RegisterScreen(self.root, self._on_auth_success)

    def _show_login(self):
        LoginScreen(self.root, self._on_auth_success, self._show_register)

    def _on_auth_success(self, username, key):
        self.root.deiconify()
        # Clear any existing widgets
        for w in self.root.winfo_children():
            w.destroy()
        Dashboard(self.root, username, key)


if __name__ == "__main__":
    App()