from cryptography.fernet import Fernet
import base64
import string


def fernet_obj_generator(key_number):
    """Function receives a key number as parameter.
    This function generates a Fernet object for encryption and decryption using the the
    given key number."""
    completion_length = 32 - len(str(key_number))
    key = str(key_number)
    for letter in string.ascii_letters:  # Make the key 32 byte long
        if completion_length == 0:
            break
        key += letter
        completion_length -= 1
    key = base64.urlsafe_b64encode(key.encode('utf-8'))  # Base64 encoding for the AES encryption
    fernet = Fernet(key)  # Since there are no punctuations it's URL safe and can be encrypted
    return fernet


def AES_encrypt(plain_msg, fernet_obj):
    """Function receives a string and a Fernet object as parameters.
    This function encrypts the supplied string using Advanced Encryption Standard (AES)
    algorithm, which the Fernet object contains, and returns the encrypted string"""
    encrypted_message = fernet_obj.encrypt(plain_msg.encode())
    return encrypted_message


def AES_decrypt(encrypted_msg, fernet_obj):
    """Function receives an encrypted string and a Fernet object as parameters.
    This function decrypts the given string using Advanced Encryption Standard (AES)
    algorithm, which the Fernet object contains, and returns the decrypted string"""
    decrypted_message = fernet_obj.decrypt(encrypted_msg)
    return decrypted_message.decode()
