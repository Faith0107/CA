from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 生成私钥
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# 生成公钥
public_key = private_key.public_key()

# 将公钥编码为PEM格式
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 将私钥编码为PEM格式
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# 保存公钥和私钥到文件
with open('public_key.pem', 'wb') as f:
    f.write(public_key_pem)

with open('private_key.pem', 'wb') as f:
    f.write(private_key_pem)

print("公钥和私钥已生成并保存")