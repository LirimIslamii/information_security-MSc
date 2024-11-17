import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import base64
import re
from tkinter import PhotoImage
    
def hash_password(password):
    password = entry_password.get()
    if not password:
        messagebox.showwarning("Kujdes", "Ju lutem shkruani një fjalëkalim përpara se të hash-ohet.")
        return
    
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
    salt_b64 = salt_var.get()
    hash_b64 = hash_var.get()

    if not password:
        messagebox.showwarning("Kujdes", "Ju lutem shkruani një fjalëkalim përpara se të verifikohet.")
        return
    if not salt_b64 or not hash_b64:
        messagebox.showwarning("Kujdes", "Nuk ka të dhëna hash ose salt për verifikim.")
        return

    salt = base64.b64decode(salt_b64)
    original_hash = base64.b64decode(hash_b64)
    new_hash = hashlib.pbkdf2_hmac('sha1', password.encode(), salt, 100000)
    if new_hash == original_hash:
        messagebox.showinfo("Sukses", "Fjalëkalimi është korrekt!")
    else:
        messagebox.showerror("Gabim", "Fjalëkalimi nuk përputhet!")

def validate_password(password):
    if len(password) < 8:
        messagebox.showerror("Gabim", "Fjalëkalimi duhet të ketë të paktën 8 karaktere!")
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
    if not password:
        label_strength.config(text="", foreground="black") 
        return
    
    strength = "Dobët"
    color = "red"
    if len(password) >= 8:
        strength = "Mesatar"
        color = "blue"
    if len(password) >= 12 and re.search(r"[A-Z]", password) and re.search(r"[0-9]", password) and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength = "I fortë"
        color = "green"
    label_strength.config(text=strength, foreground=color)

def clear():
    entry_password.delete(0, tk.END)
    salt_var.set("")
    hash_var.set("")
    entry_verify.delete(0, tk.END)
    label_strength.config(text="")

def toggle_password_visibility():
    if var_show_password.get():
        entry_password.config(show="")
        entry_verify.config(show="")
    else:
        entry_password.config(show="*")
        entry_verify.config(show="*")

root = tk.Tk()
root.title("Mbrojtja e Fjalëkalimeve me PBKDF2-SHA1")
root.geometry("500x250")
root.resizable(False, False)

salt_var = tk.StringVar()
hash_var = tk.StringVar()

tk.Label(root, text="Fjalëkalimi:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
entry_password = tk.Entry(root, show="*", width=35)
entry_password.grid(row=0, column=1, padx=10, pady=10)
entry_password.bind("<KeyRelease>", check_password_strength)
btn_hash = tk.Button(root, text="Hash Fjalëkalimin", command=lambda: hash_password(entry_password.get()))
btn_hash.grid(row=0, column=2, padx=10, pady=10, sticky='w')

label_strength = tk.Label(root)
label_strength.grid(row=1, column=1, sticky='w', padx=5, pady=0)

tk.Label(root, text="Salt:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
entry_salt = tk.Entry(root, textvariable=salt_var, state='readonly', width=35)
entry_salt.grid(row=2, column=1, padx=10, pady=10)

tk.Label(root, text="Hash:").grid(row=3, column=0, sticky='w', padx=10, pady=10)
entry_hash = tk.Entry(root, textvariable=hash_var, state='readonly', width=35)
entry_hash.grid(row=3, column=1, padx=10, pady=10)

tk.Label(root, text="Verifiko Fjalëkalimin:").grid(row=4, column=0, padx=10, pady=10)
entry_verify = tk.Entry(root, show="*", width=35)
entry_verify.grid(row=4, column=1, padx=10)

btn_verify = tk.Button(root, text="Verifiko", command=verify_password, fg='green')
btn_verify.grid(row=5, column=2, padx=(10, 2), pady=10, sticky='w')

btn_clear = tk.Button(root, text="Pastro", command=clear, fg='red')
btn_clear.grid(row=5, column=2, padx=(2, 10), pady=10, sticky='e')

var_show_password = tk.BooleanVar()
chk_show_password = tk.Checkbutton(root, text="Shfaq fjalëkalimin", variable=var_show_password, command=toggle_password_visibility)
chk_show_password.grid(row=5, column=0, padx=10, pady=10, sticky='w')

root.mainloop()
