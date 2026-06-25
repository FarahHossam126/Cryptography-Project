import customtkinter as ctk
from tkinter import messagebox, filedialog
import base64
import urllib.parse
import os
import secrets
 
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, SHA512

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
 
 
class UltimateCryptoToolkit(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Toolkit Project")
        self.geometry("1050x850")
 
        self.rsa_key = None
 
        
        self.tabview = ctk.CTkTabview(self, width=1000, height=800)
        self.tabview.pack(padx=20, pady=20)
 
        self.tab_sym    = self.tabview.add("Symmetric")
        self.tab_asym   = self.tabview.add("RSA")
        self.tab_hash   = self.tabview.add("Hashing")
        self.tab_encode = self.tabview.add("Encoding")
 
        self.setup_symmetric()
        self.setup_asymmetric()
        self.setup_hashing()
        self.setup_encoding()
 
    
    def copy_val(self, widget):
        try:
            data = widget.get("1.0", "end-1c")
            if not data:
                messagebox.showwarning("Warning", "Nothing to copy!")
                return
            try:
                import pyperclip
                pyperclip.copy(data)
            except Exception:
                
                self.clipboard_clear()
                self.clipboard_append(data)
            messagebox.showinfo("Success", "Copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
 
    
    @staticmethod
    def make_key(raw: bytes, size: int) -> bytes:
        """Pad or truncate raw bytes to exactly `size` bytes using null-byte padding."""
        return raw.ljust(size, b'\0')[:size]
 
    
    def setup_symmetric(self):
        ctk.CTkLabel(
            self.tab_sym,
            text="Symmetric Encryption (AES-GCM / DES / 3DES)",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
 
        self.sym_in = ctk.CTkTextbox(self.tab_sym, height=100, width=750)
        self.sym_in.pack(pady=5)
 
        key_row = ctk.CTkFrame(self.tab_sym, fg_color="transparent")
        key_row.pack(pady=5)
 
        self.sym_key = ctk.CTkEntry(
            key_row, width=460,
            placeholder_text="Enter Secret Key",
            show="*"          
        )
        self.sym_key.grid(row=0, column=0, padx=(0, 8))
 
        self.sym_key_visible = False
        self.sym_key_toggle_btn = ctk.CTkButton(
            key_row, text="Show", width=80,
            command=self.toggle_sym_key
        )
        self.sym_key_toggle_btn.grid(row=0, column=1)
 
        self.sym_algo = ctk.CTkOptionMenu(
            self.tab_sym, values=["AES (GCM)", "DES (CBC)", "3DES (CBC)"]
        )
        self.sym_algo.pack(pady=10)
 
        frame = ctk.CTkFrame(self.tab_sym)
        frame.pack(pady=10)
        ctk.CTkButton(
            frame, text="Encrypt", fg_color="#28a745",
            command=lambda: self.process_sym("enc")
        ).grid(row=0, column=0, padx=10)
        ctk.CTkButton(
            frame, text="Decrypt", fg_color="#dc3545",
            command=lambda: self.process_sym("dec")
        ).grid(row=0, column=1, padx=10)
 
        self.sym_out = ctk.CTkTextbox(self.tab_sym, height=120, width=750)
        self.sym_out.pack(pady=10)
        ctk.CTkButton(
            self.tab_sym, text="Copy Result",
            command=lambda: self.copy_val(self.sym_out)
        ).pack()
 
    def toggle_sym_key(self):
        self.sym_key_visible = not self.sym_key_visible
        self.sym_key.configure(show="" if self.sym_key_visible else "*")
        self.sym_key_toggle_btn.configure(
            text="Hide" if self.sym_key_visible else "Show"
        )
 
    def process_sym(self, mode):
        try:
            algo    = self.sym_algo.get()
            raw_key = self.sym_key.get().encode()
            text    = self.sym_in.get("1.0", "end-1c")
 
            if not raw_key or not text:
                raise ValueError("Key and Text are required!")
 
            # ── AES GCM ──────────────────────────────────────────────────
            if "AES" in algo:
                
                key = self.make_key(raw_key, 32)
                if mode == "enc":
                    cipher = AES.new(key, AES.MODE_GCM)
                    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
                    result = base64.b64encode(
                        cipher.nonce + tag + ciphertext
                    ).decode()
                else:
                    raw    = base64.b64decode(text)
                    nonce  = raw[:16]
                    tag    = raw[16:32]
                    ct     = raw[32:]
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    result = cipher.decrypt_and_verify(ct, tag).decode()
 
            # ── DES / 3DES CBC ────────────────────────────────────────────
            elif "DES" in algo:
                if "3DES" in algo:
                    key_len = len(raw_key)
                    if key_len not in (16, 24):
                        raise ValueError(
                    f"3DES key must be exactly 16 or 24 bytes.\n"
                    f"Your key is {key_len} byte(s).\n\n"
                    f"  16 bytes = 112-bit effective security\n"
                    f"  24 bytes = 168-bit effective security\n\n"
                    f"Please enter a key of exactly 16 or 24 characters."
                    )
                    key        = raw_key
                    cipher_mod = DES3
                    blk        = 8

                else:

                    key        = self.make_key(raw_key, 8)
                    cipher_mod = DES
                    blk        = 8
 
                if mode == "enc":
                    iv     = os.urandom(8)
                    cipher = cipher_mod.new(key, cipher_mod.MODE_CBC, iv)
                    ct     = cipher.encrypt(pad(text.encode(), blk))
                    result = base64.b64encode(iv + ct).decode()
                else:
                    raw    = base64.b64decode(text)
                    iv     = raw[:8]
                    ct     = raw[8:]
                    cipher = cipher_mod.new(key, cipher_mod.MODE_CBC, iv)
                    result = unpad(cipher.decrypt(ct), blk).decode()
 
            else:
                raise ValueError("Unknown algorithm selected.")
 
            self.sym_out.delete("1.0", "end")
            self.sym_out.insert("1.0", result)
 
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
 
    
    def setup_asymmetric(self):
        ctk.CTkLabel(
            self.tab_asym,
            text="Asymmetric RSA (2048-bit PKCS1 OAEP)",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
 
        
        key_frame = ctk.CTkFrame(self.tab_asym)
        key_frame.pack(pady=5)
        ctk.CTkButton(
            key_frame, text="Generate Key Pair",
            command=self.gen_rsa
        ).grid(row=0, column=0, padx=8)
        
        ctk.CTkButton(
            key_frame, text="Save Keys to File",
            command=self.save_rsa_keys
        ).grid(row=0, column=1, padx=8)
        ctk.CTkButton(
            key_frame, text="Load Keys from File",
            command=self.load_rsa_keys
        ).grid(row=0, column=2, padx=8)
 
        self.rsa_in = ctk.CTkTextbox(self.tab_asym, height=100, width=750)
        self.rsa_in.pack(pady=5)
 
        enc_frame = ctk.CTkFrame(self.tab_asym)
        enc_frame.pack(pady=10)
        ctk.CTkButton(
            enc_frame, text="Encrypt with Public",
            command=self.rsa_enc
        ).grid(row=0, column=0, padx=10)
        ctk.CTkButton(
            enc_frame, text="Decrypt with Private",
            command=self.rsa_dec
        ).grid(row=0, column=1, padx=10)
 
        self.rsa_out = ctk.CTkTextbox(self.tab_asym, height=180, width=750)
        self.rsa_out.pack(pady=10)
        ctk.CTkButton(
            self.tab_asym, text="Copy Keys / Result",
            command=lambda: self.copy_val(self.rsa_out)
        ).pack()
 
    def gen_rsa(self):
        self.rsa_key = RSA.generate(2048)
        pub  = self.rsa_key.publickey().export_key().decode()
        priv = self.rsa_key.export_key().decode()
        self.rsa_out.delete("1.0", "end")
        self.rsa_out.insert("1.0", f"--- PUBLIC KEY ---\n{pub}\n\n--- PRIVATE KEY ---\n{priv}")
        messagebox.showinfo("Success", "RSA 2048-bit Key Pair Generated!")
 
    
    def save_rsa_keys(self):
        if not self.rsa_key:
            messagebox.showwarning("Warning", "No keys to save! Generate keys first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            title="Save RSA Keys"
        )
        if not path:
            return
        try:
            pub  = self.rsa_key.publickey().export_key().decode()
            priv = self.rsa_key.export_key().decode()
            with open(path, "w") as f:
                f.write(f"--- PUBLIC KEY ---\n{pub}\n\n--- PRIVATE KEY ---\n{priv}\n")
            messagebox.showinfo("Success", f"Keys saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save keys:\n{str(e)}")
 
    
    def load_rsa_keys(self):
        path = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            title="Load RSA Keys"
        )
        if not path:
            return
        try:
            with open(path, "r") as f:
                content = f.read()
            
            if "PRIVATE KEY" in content:
                priv_start = content.find("-----BEGIN RSA PRIVATE KEY-----")
                if priv_start == -1:
                    priv_start = content.find("-----BEGIN PRIVATE KEY-----")
                priv_pem   = content[priv_start:]
                self.rsa_key = RSA.import_key(priv_pem.strip())
                self.rsa_out.delete("1.0", "end")
                self.rsa_out.insert("1.0", content)
                messagebox.showinfo("Success", "RSA Keys loaded successfully!")
            else:
                messagebox.showerror("Error", "No private key found in file.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys:\n{str(e)}")
 
    def rsa_enc(self):
        try:
            if not self.rsa_key:
                raise ValueError("Generate or load RSA keys first!")
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
            text = self.rsa_in.get("1.0", "end-1c").strip()
            if not text:
                raise ValueError("Input is empty!")
            aes_key = get_random_bytes(32)
            cipher_aes = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(text.encode())
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key.publickey())
            enc_key = cipher_rsa.encrypt(aes_key)
            result = base64.b64encode(
            enc_key + cipher_aes.nonce + tag + ciphertext
            ).decode()
            self.rsa_out.delete("1.0", "end")
            self.rsa_out.insert("1.0", result)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def rsa_dec(self):
        try:
            if not self.rsa_key:
                raise ValueError("Load or generate RSA keys first!")
            raw = base64.b64decode(self.rsa_in.get("1.0", "end-1c"))
            enc_key = raw[:256]     
            nonce   = raw[256:272]
            tag     = raw[272:288]
            ct      = raw[288:]
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
            aes_key = cipher_rsa.decrypt(enc_key)
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            text = cipher_aes.decrypt_and_verify(ct, tag).decode()
            self.rsa_out.delete("1.0", "end")
            self.rsa_out.insert("1.0", text)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed!")
    
    
    def setup_hashing(self):
        ctk.CTkLabel(
            self.tab_hash,
            text="Secure Salted Hashing",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        self.h_in = ctk.CTkEntry(
            self.tab_hash, width=600, placeholder_text="Text to hash"
        )
        self.h_in.pack(pady=5)
        salt_row = ctk.CTkFrame(self.tab_hash, fg_color="transparent")
        salt_row.pack(pady=5)
        self.h_salt = ctk.CTkEntry(
            salt_row, width=380,
            placeholder_text="Enter Salt (Highly Recommended)",
            show="*"          
        )
        self.h_salt.grid(row=0, column=0, padx=(0, 8))
        self.h_salt_visible = False
        self.h_salt_toggle_btn = ctk.CTkButton(
            salt_row, text="Show", width=80,
            command=self.toggle_h_salt
        )

        self.h_salt_toggle_btn.grid(row=0, column=1, padx=4)
        ctk.CTkButton(
            salt_row, text="Generate", width=80,
            command=self.generate_random_salt
        ) .grid(row=0, column=2, padx=4)
 
        self.h_algo = ctk.CTkOptionMenu(
            self.tab_hash, values=["SHA-256", "SHA-512"]
        )
        self.h_algo.pack(pady=10)
 
        ctk.CTkButton(
            self.tab_hash, text="Generate Hash", command=self.run_hash
        ).pack(pady=10)
 
        self.h_out = ctk.CTkTextbox(self.tab_hash, height=120, width=750)
        self.h_out.pack(pady=10)
        ctk.CTkButton(
            self.tab_hash, text="Copy Hash",
            command=lambda: self.copy_val(self.h_out)
        ).pack()
 
    def toggle_h_salt(self):
        self.h_salt_visible = not self.h_salt_visible
        self.h_salt.configure(show="" if self.h_salt_visible else "*")
        self.h_salt_toggle_btn.configure(
            text="Hide" if self.h_salt_visible else "Show"
        )

    def generate_random_salt(self):
        random_salt = secrets.token_hex(16)
        self.h_salt.delete(0, 'end')
        self.h_salt.insert(0, random_salt)
 
    def run_hash(self):
        try:
            text = self.h_in.get().strip()
            if not text:
                raise ValueError("Input text is empty.")
            salt = self.h_salt.get()
            data = (salt + text).encode()
            if self.h_algo.get() == "SHA-256":
                hash_val = SHA256.new(data).hexdigest()
            else:
                hash_val = SHA512.new(data).hexdigest()
            display = (
                f"Algorithm : {self.h_algo.get()}\n"
                f"Salt      : {salt if salt else '(none)'}\n"
                f"Hash      : {hash_val}"
            )
 
            self.h_out.delete("1.0", "end")
            self.h_out.insert("1.0", display)
 
        except Exception as e:
            messagebox.showerror("Error", str(e))
 
    
    def setup_encoding(self):
        ctk.CTkLabel(
            self.tab_encode,
            text="Data Encoding / Decoding",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        self.e_in = ctk.CTkTextbox(self.tab_encode, height=100, width=750)
        self.e_in.pack(pady=5)
        self.e_type = ctk.CTkOptionMenu(
            self.tab_encode, values=["Base64", "Hex", "URL"]
        )
        self.e_type.pack(pady=10)
        frame = ctk.CTkFrame(self.tab_encode)
        frame.pack(pady=10)
        ctk.CTkButton(
            frame, text="Encode", command=self.encode
        ).grid(row=0, column=0, padx=10)
        ctk.CTkButton(
            frame, text="Decode", command=self.decode
        ).grid(row=0, column=1, padx=10)
        self.e_out = ctk.CTkTextbox(self.tab_encode, height=120, width=750)
        self.e_out.pack(pady=10)
        ctk.CTkButton(
            self.tab_encode, text="Copy Output",
            command=lambda: self.copy_val(self.e_out)
        ).pack()
 
    def encode(self):
        try:
            t = self.e_in.get("1.0", "end-1c")
            if not t:
                messagebox.showwarning("Warning", "Input is empty!")
                return
            enc_type = self.e_type.get()
            if enc_type == "Base64":
                res = base64.b64encode(t.encode()).decode()
            elif enc_type == "Hex":
                res = t.encode().hex()
            else:   # URL
                res = urllib.parse.quote(t, safe='')
            self.e_out.delete("1.0", "end")
            self.e_out.insert("1.0", res)
        except Exception as e:
            messagebox.showerror("Error", str(e))
 
    def decode(self):
        try:
            t = self.e_in.get("1.0", "end-1c")
            if not t:
                messagebox.showwarning("Warning", "Input is empty!")
                return
            enc_type = self.e_type.get()
            if enc_type == "Base64":
                res = base64.b64decode(t).decode()
            elif enc_type == "Hex":
                res = bytes.fromhex(t).decode()
            else:   # URL
                res = urllib.parse.unquote(t)
            self.e_out.delete("1.0", "end")
            self.e_out.insert("1.0", res)
        except Exception as e:
            messagebox.showerror("Error", "Invalid data for decoding. Check your input.")

if __name__ == "__main__":
    app = UltimateCryptoToolkit()
    app.mainloop()