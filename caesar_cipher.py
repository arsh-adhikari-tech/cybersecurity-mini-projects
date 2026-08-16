# Semester 1 Mini Project: Caesar Cipher Tool
def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    if mode == 'decrypt':
        shift = -shift
        
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

# Test the script
secret_message = "ARSH_SECURE_PROJECT"
key = 4

encrypted = caesar_cipher(secret_message, key, mode='encrypt')
print(f"🔒 Encrypted Text: {encrypted}")

decrypted = caesar_cipher(encrypted, key, mode='decrypt')
print(f"🔓 Decrypted Text: {decrypted}")
