import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import hashlib
import os
import mysql.connector
import subprocess

password = "password"

def mode1(data):
    NCV = [];FC = [];CC = [];OF = [];Q = [];C = [];M = [];EF = [];F = [];ADe = [];EFe = [];ADh = [];EDh = []
    with open('table1.csv', 'r') as file:
        lines = file.readlines()
        k = 0
        for line in lines:
            if k == 0:
                k = 1
                continue
            FC.append(float(line.split(',')[1]));Q.append(float(line.split(',')[2]))
            C.append(float(line.split(',')[3]));M.append(float(line.split(',')[4]))
            F.append(float(line.split(',')[5]));ADe.append(float(line.split(',')[6]))
            EFe.append(float(line.split(',')[7]))
        
    with open('tableS1.csv', 'r') as file:
        lines = file.readlines()
        k = 0
        for line in lines:
            if k == 0:
                k = 1
                continue
            NCV.append(float(line.split(',')[1]));CC.append(float(line.split(',')[2]))
            OF.append(float(line.split(',')[3]));EF.append(float(line.split(',')[4]))
            ADh.append(float(line.split(',')[5]));EDh.append(float(line.split(',')[6]))
            
    Eburn = 0
    for i in range(0,len(FC)):
        Eburn += NCV[i]*FC[i]*CC[i]*OF[i]*44/12
    Egy1 = Q[0]*C[0]*44/12
    Egy2 = 0
    for i in range(0,len(M)):
        Egy2 += M[i]*EF[i]*F[i]
    Eeh = ADe[0]*EFe[0]+ADh[0]*EDh[0]
    
    return Eburn+Egy1+Egy2+Eeh

# def mode2(data):
    # same logic as above I'll just write the calculation part
    

def Calculate(data,Type):
    if Type == "glass":
        result = mode1(data)
    elif Type == "china":
        result = mode2(data)
    return result.stdout()

# 加密模块
def encode(data, password):
    salt = get_random_bytes(16)
    private_key = scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext)

# 解密模块
def decode(encoded_data, password):
    data = base64.b64decode(encoded_data)
    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    ciphertext = data[48:]
    private_key = scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Hash模块
def hash_data(data):
    return hashlib.sha256(data).hexdigest()


# 连接数据库
conn = mysql.connector.connect(
    host="location",
    user="username",
    password="password",
    database="name"
)
cursor = conn.cursor()

# 从数据库中检索数据
cursor.execute("SELECT data, key FROM SQL")
rows = cursor.fetchall()

# 解密数据
decrypted_data = [decode(row[0], row[1]) for row in rows]

# 加密新数据并生成hash值
new_data = "New data" 
encoded_data = encode(new_data, password)
data_hash = hash_data(new_data)

# 将新数据插入数据库
insert_query = "INSERT INTO SQL (data, data_hash) VALUES (%s, %s)"
cursor.execute(insert_query, (encoded_data, data_hash))
conn.commit()

# 执行计算模块，并将结果存储到数据库
calculated_value = Calculate(decrypted_data,Type)  # 假设Calculate是您的计算逻辑
update_query = "UPDATE SQL SET calculated_value = %s WHERE some_condition"
cursor.execute(update_query, (calculated_value,))
conn.commit()

cursor.close()
conn.close()
