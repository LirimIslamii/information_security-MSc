import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import base64
import re

def hash_password(password):
    if not validate_password(password):
        return
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha1', password.encode(), salt, 100000)
    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(hashed).decode()
    salt_var.set(salt_b64)
    hash_var.set(hash_b64)
    messagebox.showinfo("Sukses", "Fjalëkalimi u hash-ua me sukses!")

def verify_password():    
    password = entry_verify.get()
    salt = base64.b64decode(salt_var.get())
    original_hash = base64.b64decode(hash_var.get())
    new_hash = hashlib.pbkdf2_hmac('sha1', password.encode(), salt, 100000)
    if new_hash == original_hash:
        messagebox.showinfo("Sukses", "Fjalëkalimi është korrekt!")
    else:
        messagebox.showerror("Gabim", "Fjalëkalimi nuk përputhet!")

def validate_password(password):
    if len(password) < 8:
        messagebox.showerror("Gabim", "Fjalëkalimi duhet të jetë të paktën 8 karaktere i gjatë!")
        return False
    if not re.search(r"[A-Z]", password):
        messagebox.showerror("Gabim", "Fjalëkalimi duhet të përmbajë të paktën një shkronjë të madhe!")
        return False
    if not re.search(r"[a-z]", password):
        messagebox.showerror("Gabim", "Fjalëkalimi duhet të përmbajë të paktën një shkronjë të vogël!")
        return False
    if not re.search(r"[0-9]", password):
        messagebox.showerror("Gabim", "Fjalëkalimi duhet të përmbajë të paktën një numër!")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        messagebox.showerror("Gabim", "Fjalëkalimi duhet të përmbajë të paktën një karakter special!")
        return False
    return True

def check_password_strength(event):
    password = entry_password.get()
    strength = "Dobët"
    if len(password) >= 8:
        strength = "Mesatar"
    if len(password) >= 12 and re.search(r"[A-Z]", password) and re.search(r"[0-9]", password) and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength = "I fortë"
    label_strength.config(text=f"Fuqia: {strength}")

def clear():
    entry_password.delete(0, tk.END)
    salt_var.set("")
    hash_var.set("")
    entry_verify.delete(0, tk.END)

root = tk.Tk()
root.title("Mbrojtja e Fjalëkalimeve me PBKDF2-SHA1")
root.geometry("650x400")
root.resizable(False, False)

salt_var = tk.StringVar()
hash_var = tk.StringVar()
    
tk.Label(root, text="Fjalëkalimi:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
entry_password = tk.Entry(root, show="*", width=30)
entry_password.grid(row=0, column=1, padx=10, pady=10)
entry_password.bind("<KeyRelease>", check_password_strength)
btn_hash = tk.Button(root, text="Hash Fjalëkalimin", command=lambda: hash_password(entry_password.get()))
btn_hash.grid(row=0, column=2, padx=10, pady=10, sticky='w')

label_strength = tk.Label(root, text="Fuqia: ")
label_strength.grid(row=1, column=0, sticky='w', padx=10, pady=10)

tk.Label(root, text="Salt:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
entry_salt = tk.Entry(root, textvariable=salt_var, state='readonly', width=30)
entry_salt.grid(row=2, column=1, padx=10, pady=10)

tk.Label(root, text="Hash:").grid(row=3, column=0, sticky='w', padx=10, pady=10)
entry_hash = tk.Entry(root, textvariable=hash_var, state='readonly', width=30)
entry_hash.grid(row=3, column=1, padx=10, pady=10)

tk.Label(root, text="Verifiko Fjalëkalimin:").grid(row=4, column=0, padx=10, pady=10)
entry_verify = tk.Entry(root, show="*", width=35)
entry_verify.grid(row=4, column=1, padx=10)

btn_verify = tk.Button(root, text="Verifiko", command=verify_password)
btn_verify.grid(row=4, column=2, padx=(10, 2), pady=10, sticky='w')

btn_clear = tk.Button(root, text="Pastro", command=clear)
btn_clear.grid(row=3, column=2, padx=(2, 10), pady=10, sticky='e')

root.mainloop()