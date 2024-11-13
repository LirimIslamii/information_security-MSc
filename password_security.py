import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import base64

def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha1', password.encode(), salt, 100000)
    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(hashed).decode()
    salt_var.set(salt_b64)
    hash_var.set(hash_b64)
    messagebox.showinfo("Sukses", "Fjalëkalimi u hash-ua me sukses!")

root = tk.Tk()
root.title("Mbrojtja e Fjalëkalimeve me PBKDF2-SHA1")
root.geometry("500x190")
root.resizable(False, False) 

salt_var = tk.StringVar()
hash_var = tk.StringVar()
    
tk.Label(root, text="Fjalëkalimi:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
entry_password = tk.Entry(root, show="*", width=30)
entry_password.grid(row=0, column=1, padx=10, pady=10)
btn_hash = tk.Button(root, text="Hash Fjalëkalimin", command=lambda: hash_password(entry_password.get()))
btn_hash.grid(row=0, column=2, padx=10, pady=10, sticky='w')

tk.Label(root, text="Salt:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
entry_salt = tk.Entry(root, textvariable=salt_var, state='readonly', width=30)
entry_salt.grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="Hash:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
entry_hash = tk.Entry(root, textvariable=hash_var, state='readonly', width=30)
entry_hash.grid(row=2, column=1, padx=10, pady=10)

root.mainloop()
