import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
import base64
import os

def generate_key(key_name):
    if not os.path.exists(f"{key_name}.key"):
        key = Fernet.generate_key()
        with open(f"{key_name}.key", "wb") as key_file:
            key_file.write(key)

def load_key(key_name):
    return open(f"{key_name}.key", "rb").read()

def encrypt_message(message, key_name):
    key = load_key(key_name)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key_name):
    key = load_key(key_name)
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        return None

def write_encrypted_to_file(original_message, encrypted_message, key_name):
    with open("Encrypted Messages.txt", "a", encoding="utf-8") as file:
        file.write(f"Original Message: {original_message}\n")
        file.write(f"Криптирано съобщение: {encrypted_message.decode()}\n")
        file.write(f"Използван ключ: {key_name}\n")
        file.write("\n")

def write_decrypted_to_file(encrypted_message, decrypted_message, key_name):
    with open("Decrypted Messages.txt", "a", encoding="utf-8") as file:
        file.write(f"Криптирано съобщение: {base64.b64encode(encrypted_message).decode()}\n")
        if decrypted_message:
            file.write(f"Декриптирано съобщение: {decrypted_message} (Използван ключ: {key_name})\n")
        else:
            file.write("Декриптиране неуспешно\n")
        file.write("\n")

def encrypt_file(filename, key_name):
    try:
        with open(filename, "rb") as file:
            content = file.read()
            decoded_content = content.decode()
            encrypted_content = encrypt_message(decoded_content, key_name)
            encrypted_filename = filename + ".encrypted"
            with open(encrypted_filename, "wb") as encrypted_file:
                encrypted_file.write(encrypted_content)
            messagebox.showinfo("Успех", f"Файлът е успешно криптиран. Криптиран файл: {encrypted_filename}")
            return encrypted_filename
    except FileNotFoundError:
        messagebox.showerror("Грешка", "Файлът не е намерен.")
        return None
    except Exception as e:
        messagebox.showerror("Грешка", f"Грешка при криптиране на файла: {e}")
        return None

def decrypt_file(filename):
    try:
        with open(filename, "rb") as encrypted_file:
            encrypted_content = encrypted_file.read()
            key_name = key_var.get()
            decrypted_content = decrypt_message(encrypted_content, key_name)
            if decrypted_content:
                decrypted_filename = filename[:-10] + "_decrypted.txt"
                with open(decrypted_filename, "w", encoding="utf-8") as decrypted_file:
                    decrypted_file.write(decrypted_content)
                messagebox.showinfo("Успех", f"Файлът е успешно декриптиран. Декриптиран файл: {decrypted_filename}\n(Използван ключ: {key_name})")
            else:
                messagebox.showerror("Грешка", "Грешка при декриптиране на файла. Възможно е да сте използвали неправилен ключ.")
    except FileNotFoundError:
        messagebox.showerror("Грешка", "Криптиран файл не е намерен.")
    except Exception as e:
        messagebox.showerror("Грешка", f"Грешка при декриптиране на файла: {e}")

def encrypt_text():
    key_name = key_var.get()
    message = text_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Грешка", "Моля, въведете съобщение за криптиране.")
        return
    encrypted_message = encrypt_message(message, key_name)
    write_encrypted_to_file(message, encrypted_message, key_name)
    text_entry.delete("1.0", tk.END)
    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, encrypted_message)

def decrypt_text():
    key_name = key_var.get()
    encrypted_message = text_entry.get("1.0", tk.END).strip().encode()
    if not encrypted_message:
        messagebox.showerror("Грешка", "Моля, въведете криптирано съобщение за декриптиране.")
        return
    decrypted_message = decrypt_message(encrypted_message, key_name)
    if decrypted_message:
        write_decrypted_to_file(encrypted_message, decrypted_message, key_name)
        result_entry.delete("1.0", tk.END)
        result_entry.insert(tk.END, f"{decrypted_message} (Използван ключ: {key_name})")
    else:
        messagebox.showerror("Грешка", "Грешка при декриптиране на съобщението. Възможно е да сте използвали неправилен ключ.")

def browse_file_encrypt():
    filename = filedialog.askopenfilename()
    if filename:
        key_name = key_var.get()
        encrypt_file(filename, key_name)

def browse_file_decrypt():
    filename = filedialog.askopenfilename()
    if filename:
        decrypt_file(filename)

# Generate keys at the start
for key_name in ("key1", "key2"):
    generate_key(key_name)

# GUI setup
root = tk.Tk()
root.title("Encryption and Decryption Program")

# Style
style = ttk.Style()
style.configure("TLabel", font=("Arial", 12))
style.configure("TButton", font=("Arial", 12))
style.configure("TRadiobutton", font=("Arial", 12))

# Key selection frame
key_frame = ttk.LabelFrame(root, text="Избор на ключ")
key_frame.pack(padx=10, pady=10, fill="x")

key_var = tk.StringVar(value="key1")
ttk.Radiobutton(key_frame, text="Ключ 1", variable=key_var, value="key1").pack(side="left", padx=5, pady=5)
ttk.Radiobutton(key_frame, text="Ключ 2", variable=key_var, value="key2").pack(side="left", padx=5, pady=5)

# Text input frame
text_frame = ttk.LabelFrame(root, text="Текст за криптиране/декриптиране")
text_frame.pack(padx=10, pady=10, fill="both", expand=True)

text_entry = tk.Text(text_frame, height=10, width=80, wrap=tk.WORD, font=("Arial", 12))
text_entry.pack(padx=5, pady=5, fill="both", expand=True)

# Buttons frame
button_frame = ttk.Frame(root)
button_frame.pack(padx=10, pady=10, fill="x")

ttk.Button(button_frame, text="Криптиране на текст", command=encrypt_text).pack(side="left", padx=5, pady=5)
ttk.Button(button_frame, text="Декриптиране на текст", command=decrypt_text).pack(side="left", padx=5, pady=5)
ttk.Button(button_frame, text="Криптиране на файл", command=browse_file_encrypt).pack(side="left", padx=5, pady=5)
ttk.Button(button_frame, text="Декриптиране на файл", command=browse_file_decrypt).pack(side="left", padx=5, pady=5)

# Result frame
result_frame = ttk.LabelFrame(root, text="Резултат")
result_frame.pack(padx=10, pady=10, fill="both", expand=True)

result_entry = tk.Text(result_frame, height=10, width=80, wrap=tk.WORD, font=("Arial", 12))
result_entry.pack(padx=5, pady=5, fill="both", expand=True)

# Exit button
ttk.Button(root, text="Изход", command=root.quit).pack(pady=10)

root.mainloop()


