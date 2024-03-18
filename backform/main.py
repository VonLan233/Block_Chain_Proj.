import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import mysql.connector

def Calculate(string data[]): # Function for calculate the coins

def Encode(string s):
    key = get_random_bytes(16)
    Cipher=AES.new(key,AES.MODE_EAX)
    message = b'Hello, AES!'
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return key,ciphertext

def Decode(string s,int key):
    Cipher=AES.new(key,AES.MODE_EAX)
    decipher = AES.new(key, AES.MODE_EAX, cipher.nonce)
    plaintext = decipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def Hash(string s): # Function for encode
    hash_object = hashlib.sha256()

    message = s
    hash_object.upadate(message)

    hash_value = hash_object.hexdigest()
    
    return hash_value

user=""
password=""
option=''

with open("user.txt",'r',encoding="UTF-8") as file:
    for line in file:
        user=line[0]
        password=line[1]
        option= line[2]

if option=='Add':
    global NewData=[]
    with open("NewData.txt",'r',encoding="UTF-8") as file:
        for line in file:
            NewData.append(line)

conn = mysql.connector.connect(
    host="location",
    user="username",
    password="password",
    database="name"
)

cursor = conn.cursor()

cursor.excute("SELECT * FROM Data,Key,Hash")
data=[]
for row in cursor.fetchall():
    if Hash(row[0])==row[2]
        data.append(Decode(row[0],row[1]))
data.append(NewData)
key=[]
hash=[]
for i in NewData:
    KEY, newc=Encode(i)
    key.append(KEY)
    hash.append(Hash(i))
cursor.excute("ADD NewData,key,hash FROM Data,Key,Hash")
cursor.commit()
coins=Calculate(data)
cursor.excute("ADD Coins FROM user")
cursor.commit()
