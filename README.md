Encryption and Decryption Program
This is a Python program designed for encrypting and decrypting texts and files using the cryptography.fernet module. 
The program allows users to generate encryption keys, encrypt and decrypt messages, and work with encrypted files.


Features
-Generate Keys: Automatically generate and store encryption keys.
-Encrypt Text: Encrypt plain text messages.
-Decrypt Text: Decrypt encrypted text messages.
-Encrypt Files: Encrypt the contents of a file.
-Decrypt Files: Decrypt the contents of an encrypted file.
-Choose Between Multiple Keys: Option to choose between two keys for encryption and decryption.


Prerequisites
Python 3.6 or higher
cryptography library (install via pip install cryptography)


Installation
1.Clone the repository or download the script file.
2.Ensure you have Python 3.6 or higher installed.
3.Install the required library using pip:

pip install cryptography


Usage
Generating Keys
Keys are generated automatically when the program is first run. Two keys, key1 and key2, are generated and stored as key1.key and key2.key respectively.

Running the Program
Run the program by executing the script in a Python environment:

python encryption_program.py

The program presents a menu with the following options:
-Encrypting a text
-Decrypting a text
-Encrypting a file
-Decrypting a file
-Exit

1.Encrypting a Text
Choose the option to encrypt a text by entering 1.
Select the key (key1 or key2) to use for encryption.
Enter the message to be encrypted.
The program displays the encrypted message and saves it to Encrypted Messages.txt.

2.Decrypting a Text
Choose the option to decrypt a text by entering 2.
Enter the encrypted message.
The program attempts to decrypt the message using key1 and key2.
If successful, the decrypted message and the key used are displayed and saved to Decrypted Messages.txt.

3.Encrypting a File
Choose the option to encrypt a file by entering 3.
Select the key (key1 or key2) to use for encryption.
Enter the path to the file to be encrypted.
The program encrypts the file content and saves it as filename.encrypted.

4.Decrypting a File
Choose the option to decrypt a file by entering 4.
Enter the path to the encrypted file.
The program attempts to decrypt the file using key1 and key2.
If successful, the decrypted content is saved to filename_decrypted.txt.

5.Exiting the Program
Choose the exit option by entering 5 to terminate the program.


Error Handling
The program includes basic error handling for:

-Invalid menu choices
-Missing files
-Incorrect decryption attempts


Code Overview
Functions
-generate_key(key_name): Generates and saves a key if it doesn't already exist.
-load_key(key_name): Loads a key from a file.
-choose_key(): Prompts the user to select a key.
-encrypt_message(message, key_name): Encrypts a message using the selected key.
-decrypt_message(encrypted_message): Attempts to decrypt a message using available keys.
-write_encrypted_to_file(original_message, encrypted_message, key_name): Saves encrypted message details to a file.
-write_decrypted_to_file(encrypted_message, decrypted_message, key_name): Saves decrypted message details to a file.
-encrypt_file(filename, key_name): Encrypts the content of a specified file.
-decrypt_file(filename): Decrypts the content of a specified encrypted file.

Main Program Loop
The main loop provides a menu-driven interface for users to select encryption and decryption operations, handle file input/output, and manage key selection.


Notes
-Ensure the cryptography library is installed before running the program.
-Keep the generated keys secure; losing them means losing the ability to decrypt messages and files encrypted with those keys.
-The program appends encrypted and decrypted message details to text files (Encrypted Messages.txt and Decrypted Messages.txt).


License
This project is open-source and available under the MIT License.

Contribution
Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.
