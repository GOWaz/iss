import socket
import random
import gnupg
import os
from Crypto.Cipher import AES
from datetime import datetime, timedelta

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

usersPath = 'users'
keyName = 'public_key/public_key.acs'
passphraseName = 'password/passphrase.pwd'

tcp_port = 1672  # 9999
tcp_ip = '127.0.0.1'  # 'localhost'

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((tcp_ip, tcp_port))


def connect_gpg():
    gpg = gnupg.GPG(gnupghome='C:/Users/abdul/AppData/Roaming/gnupg',
                    gpgbinary='c:/Program Files (x86)/GnuPG/bin/gpg')
    gpg.encoding = 'utf-8'
    return gpg


def login(option):
    try:
        client.send(option.encode())
        username = input('Username: ')
        client.send(username.encode())
        client.send(input('Password: ').encode())
        msg = client.recv(1024).decode()
        if msg.strip() == '1':
            print('login successful')
            return True, username
        else:
            return False, None

    except Exception as e:
        print('[LOGIN] Exception at:', e)


def sign_up():
    try:
        client.send('2'.encode())
        client.send(input('New Username: ').encode())
        client.send(input('New password: ').encode())
        client.send(input('Account type \n[S]Student. \n[P]Professor. \nTYPE: ').encode())
        print('[SERVER]', client.recv(1024).decode())
    except Exception as e:
        print('[SIGNUP] Exception at:', e)


def fill_info(username):
    try:
        status = client.recv(1024).decode()
        if status.strip() == '1':
            print('Fill the rest of your info:')
            key = str(random.randint(1000000000000000, 9999999999999999)).encode()
            client.send(key)
            nonce = str(random.randint(1000000000000000, 9999999999999999)).encode()
            client.send(nonce)
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            phone_input = input('Phone number: ').encode()
            residence_input = input('Residence: ').encode()
            # client.send(cipher.encrypt(phone_input.ljust(len(phone_input))))
            # client.send(cipher.encrypt(residence_input.ljust(len(residence_input))))
            client.send(cipher.encrypt(phone_input))
            client.send(cipher.encrypt(residence_input))
            print('[SERVER]', client.recv(1024).decode())
            prk, ppk = create_client_key()
            save_client_private_key(prk, username)
            client.send(str(ppk).encode())
        else:
            pass
    except Exception as e:
        print('[FILL_INFO] Exception at:', e)


def connect_with_server():
    try:
        client.send('SYN'.encode())
        msg = client.recv(1024).decode()
        client.send(msg.encode())
        status = client.recv(1024).decode()
        if status.strip() == '1':
            print('[CONNECTED]')
        else:
            print('[DENIED]')

    except Exception as e:
        print('[SERVER_CONNECTION] Exception at:', e)


def get_server_public_key():
    try:
        sPpk = client.recv(2024).decode()
        return sPpk
    except Exception as e:
        print('[SERVER_PUBLIC_KEY] Exception at:', e)


def send_session_key(pk):
    try:
        key = str(random.randint(1000000000000000, 9999999999999999)).encode()
        nonce = str(random.randint(1000000000000000, 9999999999999999)).encode()
        gpg = connect_gpg()
        encrypted_key = gpg.encrypt(key, recipients=pk)
        encrypted_nonce = gpg.encrypt(nonce, recipients=pk)
        print('[SENDING] Session key ....')
        client.send(str(encrypted_key).encode())
        client.send(str(encrypted_nonce).encode())
        print('[SENT] Session key !')
        return key, nonce
    except Exception as e:
        print('[SESSION_KEY] Exception at:', e)


def send_message(key, nonce):
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        message = input('Enter message: ').encode()
        print('[SENDING] Message ....')
        client.send(cipher.encrypt(message.ljust(len(message))))
        print('[SENT] Message !')
    except Exception as e:
        print('[MESSAGE] Exception at:', e)


def connect_and_send():
    try:
        client.send('3'.encode())
        connect_with_server()
        ppk = get_server_public_key()
        key, nonce = send_session_key(ppk)
        send_message(key, nonce)
    except Exception as e:
        print('[CONNECTION] Exception at:', e)


def get_client_passphrase(username):
    try:
        passFullPath = os.path.join(usersPath, username, passphraseName)
        if os.path.exists(passFullPath):
            with open(passFullPath, 'r') as pass_file:
                passphrase = pass_file.read()
            return passphrase
    except Exception as e:
        print('[PASSPHRASE] Exception at:', e)


def get_client_public_key(username):
    try:
        keyFullPath = os.path.join(usersPath, username, keyName)
        if os.path.exists(keyFullPath):
            with open(keyFullPath, 'r') as public_file:
                public_key = public_file.read()
            return public_key
    except Exception as e:
        print('[KEY] Exception at:', e)


def get_recipients(ppk):
    try:
        gpg = connect_gpg()
        public_key = ppk
        import_result = gpg.import_keys(public_key)
        if import_result.count == 1:
            fingerprint = import_result.results[0]['fingerprint']
            return fingerprint
        else:
            print("Error importing the key.")
    except Exception as e:
        print('[RECIPIENTS!] Exception at:', e)


def get_key_id(recipients):
    gpg = connect_gpg()
    keys = gpg.list_keys()
    keyID = None
    for key in keys:
        if recipients in key['fingerprint']:
            key_id = key['keyid']
            keyID = key_id
            # fingerprint = key['fingerprint']
            break
    return keyID


def sign_message(kId, passphrase):
    try:
        gpg = connect_gpg()

        msg = input('Message: ')
        signed_msg = gpg.sign(msg, keyid=kId, passphrase=passphrase)
        return signed_msg
    except Exception as e:
        print('[SIGN] Exception at:', e)


def encrypt_message(msg):
    try:
        gpg = connect_gpg()
        ppk = get_server_public_key()
        encrypted_message = gpg.encrypt(msg.data, recipients=ppk)
        return encrypted_message
    except Exception as e:
        print('[SIGN_ENCRYPTION] Exception at:', e)


def signIn_and_sign():
    try:
        option = '4'
        status, username = login(option)
        access = client.recv(1024).decode()
        if status and access.strip() == '1':
            ppk = get_client_public_key(username)
            recipients = get_recipients(ppk)
            key_id = get_key_id(recipients)
            passphrase = get_client_passphrase(username)
            msg = sign_message(key_id, passphrase)
            encrypted_message = encrypt_message(msg)
            print('[SENDING] Message ....')
            client.send(str(encrypted_message).encode())
            print('[SENT] Message !')
            print('[SERVER]', client.recv(1024).decode())
        else:
            print('[ACCESS] Denied account type must be Professor')
    except Exception as e:
        print('[SIGN_ENCRYPT] Exception at:', e)


def save_client_private_key(key, username):
    try:
        path = os.path.join('../users', username, 'RSA')
        os.makedirs(path)
        path = os.path.join('../users', username, 'RSA', 'c_private_key.pem')
        with open(path, "wb") as key_file:
            key_file.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    except Exception as e:
        print('[SAVE_KEY] Exception at:', e)


def load_client_private_key(username):
    try:
        path = os.path.join('../users', username, 'RSA', 'c_private_key.pem')
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # No password protection on the private key
                backend=default_backend()
            )
            return private_key
    except Exception as e:
        print('[LOAD_KEY] Exception at:', e)


def create_client_key():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_key_pem
    except Exception as e:
        print('[CLIENT_KEY] Exception at:', e)


def sign_certificate(subject, issuer, prk):
    try:
        issuer_key = prk
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            prk.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(issuer_key, hashes.SHA256(), default_backend())
        return cert
    except Exception as e:
        print('[SIGN_CER] Exception at:', e)


def create_client_certificate(username, title, prk):
    try:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'SY'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, username),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'Damascus'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Damascus University'),
            x509.NameAttribute(NameOID.TITLE, title)
        ])
        cert = sign_certificate(subject, issuer, prk)
        return cert.public_bytes(serialization.Encoding.PEM)
    except Exception as e:
        print('[SUBJECTS] Exception at:', e)


def generate_csr():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    req = crypto.X509Req()
    req.get_subject().CN = "damascus.edu"
    req.set_pubkey(key)
    req.sign(key, "sha256")
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

# def generate_csr():
#     key = crypto.PKey()
#     key.generate_key(crypto.TYPE_RSA, 2048)
#
#     req = crypto.X509Req()
#     subj = req.get_subject()
#     subj.C = "SY"  # Country Name (C)
#     subj.ST = "CA"  # State or Province Name (ST)
#     subj.L = "Damascus"  # Locality Name (L)
#     subj.O = "Damascus University" # Organization Name (O)
#     req.set_pubkey(key)
#     req.sign(key, "sha256")
#
#     return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)


def save_signed_certificate(username, cert):
    try:
        path = os.path.join('../users', username, 'RSA', 'received_certificate.pem')
        with open(path, "wb") as cert_file:
            cert_file.write(cert)
    except Exception as e:
        print('[SAVE_CER] Exception at:', e)


def get_client_certificate(username):
    try:
        path = os.path.join('../users', username, 'RSA', 'received_certificate.pem')
        with open(path, "rb") as received_cert_file:
            cert = received_cert_file.read()
            # cert = x509.load_pem_x509_csr(csr_file.read(), default_backend())
            # received_cert_data = received_cert_file.read()
            # received_cert = x509.load_pem_x509_certificate(received_cert_data, default_backend())
            return cert
    except Exception as e:
        print('[CLIENT_CER] Exception as e:', e)


def certificate():
    try:
        option = '5'
        status, username = login(option)
        print(client.recv(1024).decode())
        # prk = load_client_private_key(username)
        # cert = create_client_certificate(username, title, prk)
        cert = generate_csr()
        client.sendall(cert)
        print('[SERVER] ', client.recv(1024).decode())
        client.send(input('ENTER SOLUTION: ').encode())
        print('[SERVER] ', client.recv(1024).decode())
        signed_cert = client.recv(4096)
        save_signed_certificate(username, signed_cert)
    except Exception as e:
        print(e)


def close_connection():
    client.close()


def start():
    try:
        option = input(
            "Choose an option \n[1] for Login.\n[2] for Sign up.\n[3] for connect and send.\n[4] for connect sign and send. \n[5] Request a certificate. \n[6] Verify certificate. \nOPTION: ")

        if option.strip() == '1':
            state, username = login(option.strip())
            if state:
                fill_info(username)
            else:
                print('login failed')
        elif option.strip() == '2':
            sign_up()
        elif option.strip() == '3':
            connect_and_send()
        elif option.strip() == '4':
            signIn_and_sign()
        elif option.strip() == '5':
            certificate()
        elif option.strip() == '6':
            state, username = login(option.strip())
            if state:
                cert = get_client_certificate(username)
                client.sendall(cert)
        else:
            pass
        close_connection()
    except Exception as e:
        print('[INPUT] Exception at:', e)


if __name__ == "__main__":
    start()
