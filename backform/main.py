import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import hashlib
import os
import mysql.connector

def Calculate(data):
    # 这里是计算逻辑
    return sum(data)

# 加密模块
def encode(data, password):
    salt = get_random_bytes(16)
    private_key = scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()

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
    return hashlib.sha256(data.encode()).hexdigest()


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
calculated_value = Calculate(decrypted_data)  # 假设Calculate是您的计算逻辑
update_query = "UPDATE SQL SET calculated_value = %s WHERE some_condition"
cursor.execute(update_query, (calculated_value,))
conn.commit()

cursor.close()
conn.close()
