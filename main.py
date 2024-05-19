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

def choose_key():
    while True:
        print("Choose Key:")
        print("1. Key 1")
        print("2. Key 2")
        choice = input("Choose Key (1/2): ").strip()
        if choice in ('1', '2'):
            return f"key{choice}"
        else:
            print("Invalid Choice. Please try again.")

def encrypt_message(message, key_name):
    key = load_key(key_name)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    for key_name in ("key1", "key2"):  # Проверяваме с всички налични ключове
        key = load_key(key_name)
        f = Fernet(key)
        try:
            decrypted_message = f.decrypt(encrypted_message).decode()
            return decrypted_message, key_name
        except Exception as e:
            continue
    return None, None

def write_encrypted_to_file(original_message, encrypted_message, key_name):
    with open("Encrypted Messages.txt", "a", encoding="utf-8") as file:
        file.write(f"Original Message : {original_message}\n")
        file.write(f"Encrypted Message : {encrypted_message.decode()}\n")
        file.write(f"Used Key: {key_name}\n")
        file.write("\n")

def write_decrypted_to_file(encrypted_message, decrypted_message, key_name):
    with open("Decrypted Messages.txt", "a", encoding="utf-8") as file:
        file.write(f"Encrypted Message : {base64.b64encode(encrypted_message).decode()}\n")
        if decrypted_message:
            file.write(f"Decrypted Message : {decrypted_message} (Used Key : {key_name})\n")
        else:
            file.write("Decryption Unsuccessful\n")
        file.write("\n")

def encrypt_file(filename, key_name):
    try:
        with open(filename, "rb") as file:
            content = file.read()
            print("File Contains : ", content)  # Debug отпечатване
            decoded_content = content.decode()  # Декодиране на съдържанието от байтове към текст
            encrypted_content = encrypt_message(decoded_content, key_name)  # Криптиране на текста
            print("Encrypted Content : ", encrypted_content)  # Debug отпечатване
            encrypted_filename = filename + ".encrypted"
            with open(encrypted_filename, "wb") as encrypted_file:
                encrypted_file.write(encrypted_content)
            print(f"File has been succesfully encrypted. Encrypted file : {encrypted_filename} \n")
            return encrypted_filename
    except FileNotFoundError:
        print("File not found.")
        return None
    except Exception as e:
        print(f"Error in encrypting the file : {e}")
        return None

def decrypt_file(filename):
    try:
        with open(filename, "rb") as encrypted_file:
            encrypted_content = encrypted_file.read()
            decrypted_content, key_name = decrypt_message(encrypted_content)
            if decrypted_content:
                decrypted_filename = filename[:-10] + "_decrypted.txt"  # Създаване на ново име за декриптирания файл
                with open(decrypted_filename, "w", encoding="utf-8") as decrypted_file:  # Запис на декриптирания файл
                    decrypted_file.write(decrypted_content)
                print(f"File succesfully decrypted. Decrypted file : {decrypted_filename} \n")
                print(f"(Used Key: {key_name}) \n")
            else:
                print("Error in decrypting the file. \n")
    except FileNotFoundError:
        print("File not found.")
    except Exception as e:
        print(f"Error in decrypting the file : {e}")


if __name__ == "__main__":
    for key_name in ("key1", "key2"):  # Генериране на всички ключове
        generate_key(key_name)

    while True:
        print("\n Hello! This is a program for crypting and decrypting texts and files. Please choose one of the following:")
        print("1. Encrypting a text")
        print("2. Decrypting a text")
        print("3. Encrypting a file")
        print("4. Decrypting a file")
        print("5. Exit")
        choice = input("Choose an option (1/2/3/4/5): ").strip()

        if choice == '1':
            key_name = choose_key()
            message = input("Enter a message to be encrypted : ")
            encrypted_message = encrypt_message(message, key_name)
            print(f"Encrypted message : {encrypted_message} \n")
            write_encrypted_to_file(message, encrypted_message, key_name)

        elif choice == '2':
            encrypted_message = input("Enter an encrypted message to be decrypted : ")
            decrypted_message, key_name = decrypt_message(encrypted_message.encode())
            if decrypted_message:
                print(f"Decrypted message : {decrypted_message} (Used Key : {key_name}) \n")
            write_decrypted_to_file(encrypted_message.encode(), decrypted_message, key_name)

        elif choice == '3':
            key_name = choose_key()
            filename = input("Enter the path to the file you want to encrypt: ")
            encrypt_file(filename, key_name)

        elif choice == '4':
            filename = input("Enter the path to the encrypted file you want to decrypt: ")
            decrypt_file(filename)

        elif choice == '5':
            print("GoodBye !")
            break

        else:
            print("Invalid Choice. Please choose between '1', '2', '3', '4' and '5'.")
