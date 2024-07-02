import socket
import json
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# 生成CA私钥、公钥和自签证书并保存到文件
def generate_ca_keys():
    if not os.path.exists('ca_private_key.pem') or not os.path.exists('ca_certificate.pem'):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # 保存私钥
        with open('ca_private_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # 提取公钥并保存
        public_key = private_key.public_key()
        with open('ca_public_key.pem', 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # 生成自签名证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Some-State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Some-City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"myCA"),
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # 保存CA证书
        with open("ca_certificate.pem", "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

# 加载CA私钥
def load_ca_private_key():
    with open('ca_private_key.pem', 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# 加载CA证书
def load_ca_certificate():
    with open("ca_certificate.pem", "rb") as f:
        ca_cert_pem = f.read()
    return x509.load_pem_x509_certificate(ca_cert_pem, default_backend())

# 生成用户证书
def generate_user_certificate(ca_private_key, ca_cert, country, state, city, organization, common_name):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    return user_cert

# 初始化生成CA私钥、公钥和自签证书
generate_ca_keys()
ca_private_key = load_ca_private_key()
ca_cert = load_ca_certificate()

# 创建吊销列表文件
if not os.path.exists('revoked_certs.json'):
    with open('revoked_certs.json', 'w') as f:
        json.dump([], f)

# 加载吊销列表
def load_revoked_certs():
    with open('revoked_certs.json', 'r') as f:
        return json.load(f)

# 保存吊销列表
def save_revoked_certs(revoked_certs):
    with open('revoked_certs.json', 'w') as f:
        json.dump(revoked_certs, f)

# 记录已签发的证书信息
def record_cert_info(common_name, serial_number):
    cert_info = {
        "common_name": common_name,
        "serial_number": serial_number
    }
    if os.path.exists('issued_certs.json'):
        with open('issued_certs.json', 'r') as f:
            issued_certs = json.load(f)
    else:
        issued_certs = []

    issued_certs.append(cert_info)
    with open('issued_certs.json', 'w') as f:
        json.dump(issued_certs, f)

# 验证证书的所有者
def verify_cert_owner(cert_pem, common_name):
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name:
        return True
    return False

# 创建服务器套接字
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 12345))
server_socket.listen(5)
print("服务器已启动，等待连接...")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"连接来自 {client_address}")
    
    try:
        data = client_socket.recv(4096).decode('utf-8')
        request = json.loads(data)

        if request['action'] == 'apply':
            country = request['country']
            state = request['state']
            city = request['city']
            organization = request['organization']
            common_name = request['common_name']

            user_cert = generate_user_certificate(ca_private_key, ca_cert, country, state, city, organization, common_name)
            user_cert_pem = user_cert.public_bytes(serialization.Encoding.PEM)
            record_cert_info(common_name, user_cert.serial_number)

            client_socket.send(user_cert_pem)
            print("证书生成并发送给客户端")

        elif request['action'] == 'validate':
            cert_pem = request['cert']
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
                ca_public_key = ca_cert.public_key()
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )

                revoked_certs = load_revoked_certs()
                if cert.serial_number in revoked_certs:
                    response = json.dumps({"status": "revoked"})
                else:
                    response = json.dumps({"status": "valid"})
            except Exception as e:
                response = json.dumps({"status": "invalid", "error": str(e)})
            client_socket.send(response.encode('utf-8'))

        elif request['action'] == 'revoke':
            cert_pem = request['cert']
            common_name = request['common_name']

            if verify_cert_owner(cert_pem, common_name):
                cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
                revoked_certs = load_revoked_certs()
                if cert.serial_number not in revoked_certs:
                    revoked_certs.append(cert.serial_number)
                    save_revoked_certs(revoked_certs)
                    response = json.dumps({"status": "revoked"})
                else:
                    response = json.dumps({"status": "already_revoked"})
            else:
                response = json.dumps({"status": "unauthorized"})

            client_socket.send(response.encode('utf-8'))

    except Exception as e:
        print(f"处理请求时发生错误: {e}")
    
    finally:
        client_socket.close()

