import base64
import hashlib
from AESCipher import AESCipher
from PIL import Image
from random import randint
import smtplib
from email.message import EmailMessage
import imghdr
import requests
global key



class Encrypter:
    global key
    def __init__(self, text,key):
        self.text = text
        self.key =  key
   
    def encrypt_image(self):
        aes = AESCipher(self.key)
        cipher = aes.encrypt(self.text)
        return cipher

