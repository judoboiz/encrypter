from cryptography.fernet import Fernet
import hashlib
import os

FILE_KEY_PATH = "filekey.key"
HASH_PATH = "hash.txt"
ENCRYPTED_FILES_DIR = "encrypted-file.txt"

class Main:
    def __init__(self):
        key, password_hash = self.read_config()
        if not self.verify_password(key, password_hash):
            print("Password is incorrect")
            return
        
        print("Password is correct")
        try:
            three_digit_key = int(input("3 digit password: "))
        except ValueError:
            print("Must be a number")
            return
                  
        if len(str(three_digit_key)) != 3:
            print("Not a valid key")
            print("Must be three numbers")
            return
        
        three_digit_password = f"{password_hash}{three_digit_key}="
        print(three_digit_password)
        
        decrypted_key = self.decrypt(three_digit_password, key)
        print(decrypted_key)
        
        file_path = self.find_files(ENCRYPTED_FILES_DIR)
        
        options = int(input("Encrypt/Decrypt (0/1): "))
        
   
        with open(file_path, "rb") as f:
                file_code = f.read()
            
        print(decrypted_key)
            
        if options == 0:
            file_code_encrypted = self.encrypt(decrypted_key ,file_code)
        elif options == 1:
            file_code_encrypted = self.decrypt(decrypted_key ,file_code)
        else:
            print("Invalid option")
            return
            
        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.write(file_code_encrypted)
            
    def read_config(self):
        with open(FILE_KEY_PATH, "rb") as filekey:
            key = filekey.read()
            
        with open(HASH_PATH, "rb") as hash_file:
            password_hash = hash_file.read().decode("utf-8").rstrip()
        
        return key, password_hash
        
    def verify_password(self, key, password_hash):
        password_real = input("Password: ")
        return password_hash == self.hash_password(password_real)
    
    def hash_password(self ,password_real):
        password_real = str(password_real).encode(encoding = 'UTF-8', errors = 'strict')
        return hashlib.sha1(password_real).hexdigest()
    
    def decrypt(self ,key ,data):
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(data)
        return decrypted_data
    
    def encrypt(self ,key ,data):
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        return encrypted_data
    
    def find_files(self ,mypath):
        f = []
        for (dirpath, dirnames, filenames) in os.walk(mypath):
            f.extend(filenames)
            break
        
        return mypath
    
if __name__ == "__main__":
    Main()