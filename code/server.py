import random
import sqlite3
import hashlib
import socket
import threading
from Crypto.Cipher import AES
import gnupg
import os
import json
import datetime
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import serverKeys

tcp_ip = '0.0.0.0'  # 'localhost'
tcp_port = 1672  # 9999
usersPath = 'users'
serverPath = 'server'
serverKnPPath = os.path.join(serverPath, 'key_password')
savedPath = os.path.join(serverPath, 'saved')

if os.path.exists(usersPath):
    pass
else:
    os.mkdir(usersPath)

if os.path.exists(serverPath):
    pass
else:
    os.mkdir(serverPath)
    os.makedirs(serverKnPPath)
    os.mkdir(savedPath)
    serverKeys.generate_server_keys()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((tcp_ip, tcp_port))
server.listen()


def connect_to_db():
    conn = sqlite3.connect('userDB.db')
    cur = conn.cursor()
    return conn, cur


def connect_gpg():
    gpg = gnupg.GPG(gnupghome='C:/Users/abdul/AppData/Roaming/gnupg',
                    gpgbinary='c:/Program Files (x86)/GnuPG/bin/gpg')
    gpg.encoding = 'utf-8'
    return gpg


def save_user_passPhrase(username, password):
    try:
        path = os.path.join(usersPath, str(username))
        path = os.path.join(path, 'password')
        os.makedirs(path)
        passPath = os.path.join(path, 'passphrase.pwd')
        with open(passPath, 'w') as public_file:
            public_file.write(password)
    except Exception as e:
        print('[SAVE_PASSPHRASE] Exception at:', e)


def return_type(option):
    if option.strip() == 's':
        return 'Student'
    else:
        return 'Professor'


def signup(c):
    try:
        conn, cur = connect_to_db()
        new_username = c.recv(1024).decode()
        new_password = c.recv(1024).decode()
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        accountType = c.recv(1024).decode()
        cur.execute('INSERT INTO users (username, password, type) VALUES (?, ?, ?)',
                    (new_username, hashed_password, accountType))
        conn.commit()
        conn.close()
        save_user_passPhrase(new_username, hashed_password)
        c.send(f'Sign up successful as [{return_type(accountType).upper()}]. Please log in.'.encode())
    except Exception as e:
        print('[SIGNUP] Exception at:', e)


def login(c):
    try:
        conn, cur = connect_to_db()
        username = c.recv(1024).decode()
        password = c.recv(1024).decode()
        password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = cur.fetchone()
        if user:
            conn.close()
            c.send('1'.encode())
            return True, user
        else:
            c.send('2'.encode())
            return False
    except Exception as e:
        print('[LOGIN] Exception at:', e)


def info(c, details):
    try:
        conn, cur = connect_to_db()
        key = c.recv(16)
        nonce = c.recv(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        phoneNumber = c.recv(1024)
        residence = c.recv(1024)
        phoneNumber = cipher.decrypt(phoneNumber).decode().strip('\x00')
        residence = cipher.decrypt(residence).decode().strip('\x00')
        cur.execute('INSERT INTO userDetails (user_id, phone_number, residence) VALUES (?, ?, ?)',
                    (details[0], phoneNumber, residence))
        cur.execute('UPDATE users SET first_login = ? WHERE id = ?', (0, details[0]))
        conn.commit()
        conn.close()
        c.send('User details inserted successfully.'.encode())
    except Exception as e:
        print('[INFO] Exception at:', e)


def save_user_public_key(public_key, username):
    try:
        keyPath = f'{username}/public_key'
        path = os.path.join(usersPath, keyPath)
        os.makedirs(path)
        filePath = os.path.join(path, 'public_key.acs')
        with open(filePath, 'w') as public_file:
            public_file.write(public_key)
    except Exception as e:
        print('[USER_PPK] Exception at:', e)


# noinspection PyTypeChecker
def generate_users_keys(details):
    try:
        conn, cur = connect_to_db()
        gpg = connect_gpg()
        input_data = gpg.gen_key_input(name_email=details[1], passphrase=details[2], key_type='RSA', key_length=1024)
        key = gpg.gen_key(input_data)
        public_key = gpg.export_keys(key.fingerprint)
        cur.execute('INSERT INTO keys (user_id, public_key) VALUES (?, ?)', (details[0], public_key))
        conn.commit()
        conn.close()
        save_user_public_key(public_key, details[1])
    except Exception as e:
        print('[USER_KEY] Exception at:', e)


def get_server_public_key():
    try:
        keyPath = 'server/key_password/server_public_key.asc'
        if os.path.exists(keyPath):
            with open(keyPath, 'r') as public_file:
                public_key = public_file.read()
            return public_key
    except Exception as e:
        print('[KEY] Exception at:', e)


def get_server_passphrase():
    try:
        serverPassphrasePath = 'server/ke_password/server_passphrase.pwd'
        if os.path.exists(serverPassphrasePath):
            with open(serverPassphrasePath, 'r') as public_file:
                serverPassphrase = public_file.read()
            return serverPassphrase
    except Exception as e:
        print('[KEY] Exception at:', e)


def get_recipients():
    try:
        gpg = connect_gpg()
        public_key = get_server_public_key()
        import_result = gpg.import_keys(public_key)
        if import_result.count == 1:
            fingerprint = import_result.results[0]['fingerprint']
            return fingerprint
        else:
            print("Error importing the key.")
    except Exception as e:
        print('[RECIPIENTS] Exception at', e)


def handshake(c):
    try:
        message = c.recv(1024).decode()
        if message == 'SYN':
            c.send('SYN-ACK'.encode())
            message = c.recv(1024).decode()
            if message == 'SYN-ACK':
                c.send('1'.encode())
            else:
                c.send('0'.encode())
        else:
            c.send('0'.encode())
    except Exception as e:
        print('[HANDSHAKE] Exception at:', e)


def send_server_public_key(c):
    try:
        recipients = get_recipients()
        c.send(recipients.encode())
    except Exception as e:
        print('[SERVER_KEY] Exception at:', e)


# noinspection PyTypeChecker
def decrypt_session_key(eKey, eNonce):
    try:
        gpg = connect_gpg()
        key = gpg.decrypt(str(eKey), passphrase='2048')
        nonce = gpg.decrypt(str(eNonce), passphrase='2048')
        return key, nonce
    except Exception as e:
        print('[DECRYPT_SESSION_KEY] Exception at:', e)


def recv_session_key(c):
    try:
        eKey = c.recv(1024).decode()
        eNonce = c.recv(1024).decode()
        key, nonce = decrypt_session_key(eKey, eNonce)
        key = str(key).encode()
        nonce = str(nonce).encode()
        return key, nonce
    except Exception as e:
        print('[SESSION_KEY] Exception at:', e)


def recv_messages(c, key, nonce):
    try:
        message = c.recv(1024)
        print('before:', message)
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        msg = cipher.decrypt(message).decode().strip('\x00')
        print('after:', msg)
    except Exception as e:
        print('[MESSAGE] Exception at:', e)


def connect_and_recv(c):
    try:
        handshake(c)
        ppk = get_recipients()
        c.send(ppk.encode())
        key, nonce = recv_session_key(c)
        recv_messages(c, key, nonce)
    except Exception as e:
        print('[CONNECTION] Exception at:', e)


def save_verified(msg, verified, username):
    try:
        date = datetime.datetime.now()
        data = {'Username': username,
                'UserKey': str(verified.username),
                'KeyID': str(verified.pubkey_fingerprint),
                'SignatureStatus': str(verified.status),
                'TrustLvl': str(verified.trust_level),
                'Date': str(datetime.datetime.now()),
                'Contain': str(msg)}
        path = os.path.join(savedPath, f'{username}_{date.second}.json')
        with open(path, 'w') as file:
            json.dump(data, file)
    except Exception as e:
        print('[SAVE_VERIFIED] Exception at:', e)


# noinspection PyTypeChecker
def decrypt_and_verify(c, msg, username):
    try:
        gpg = connect_gpg()
        decrypted_message = gpg.decrypt(msg, passphrase='2048')
        decrypted_data = gpg.verify(decrypted_message.data)
        if decrypted_data.valid:
            message = gpg.decrypt(decrypted_message.data)
            save_verified(message, decrypted_data, username)
            signer_name = decrypted_data.username
            signer_email = decrypted_data.pubkey_fingerprint
            print(f"The document was signed by {signer_name} with the key ID: {signer_email}")
            print('Contain: ', message)
            c.send(str(f'APPROVED at: [{datetime.datetime.now()}]').encode())
        else:
            print("The signature is not valid or the document was not signed.")
            c.send(str(f'DENIED at: {datetime.datetime.now()}').encode())
    except Exception as e:
        print('[DECRYPTION_VERIFICATION] Exception at:', e)


def verified_connection(c):
    try:
        status, loginInfo = login(c)
        if status:
            if loginInfo[4] == 'p':
                c.send('1'.encode())
                ppk = get_recipients()
                c.send(ppk.encode())
                msg = c.recv(1024).decode()
                decrypt_and_verify(c, msg, loginInfo[1])
            else:
                c.send('0'.encode())
    except Exception as e:
        print('[VERIFIED_CONNECTION] Exception at:', e)


def recv_cerKey(c, uId):
    try:
        conn, cur = connect_to_db()
        key = c.recv(1024).decode()
        cur.execute('INSERT INTO cerKey (user_id, public_key) VALUES (?, ?)', (uId, key))
        conn.commit()
        conn.close()
        path = os.path.join(serverPath, f'{uId}')
        os.mkdir(path)
        path = os.path.join(path, 'public_key.pem')
        with open(path, 'w') as f:
            f.write(key)
        print('KEY INSERTED')
    except Exception as e:
        print('[RECV_CER_KEY] Exception at:', e)


# def generate_problem():
#     a = random.randint(1, 10)
#     b = random.randint(1, 10)
#     c = random.randint(1, 10)
#     operator = random.choice(['+', '-', '*'])
#
#     if operator == '+':
#         problem = f"Solve for x: {a}x * {b} = {c}"
#         solution = (c - b) / a
#     elif operator == '-':
#         problem = f"Solve for x: {a}x * {b} = {c}"
#         solution = (c + b) / a
#     else:
#         problem = f"Solve for x: {a}x * {b} = {c}"
#         solution = c / (a * b)
#
#     return solution, problem


def generate_math_problem():
    num1 = random.randint(1, 20)
    num2 = random.randint(1, 20)
    operator = random.choice(['+', '-', '*', '/'])

    if operator == '+':
        solution = num1 + num2
    elif operator == '-':
        solution = num1 - num2
    elif operator == '*':
        solution = num1 * num2
    else:
        # Ensure the division results in a whole number for simplicity
        num1 = num2 * random.randint(1, 10)
        solution = num1 // num2

    return f"What is {num1} {operator} {num2}?", solution


def send_math_problem(c):
    try:
        problem, solution = generate_math_problem()
        c.send(problem.encode())
        user_answer = float(c.recv(1024).decode())
        if user_answer == solution:  # Allowing a small tolerance for float comparison
            c.send("Correct!".encode())
            return True
        else:
            c.send("Incorrect!".encode())
            return False
    except Exception as e:
        print('[MATH] Exception at:', e)


# def get_client_public_key(uId):
#     try:
#         conn, cur = connect_to_db()
#         cur.execute('SELECT * FROM cerKey WHERE user_id = ?', (uId,))
#         result = cur.fetchone()
#         if result:
#             pem_data_bytes = result[1]  # Decode bytes to string
#             # Extract the inner bytes (remove wrapping "b" and quotes)
#             pem_data = pem_data_bytes.strip().strip("b'").encode("utf-8")
#             public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
#             return public_key
#     except Exception as e:
#         print('[CER_PPK] Exception at:', e)
def get_client_public_key(uId):
    try:
        path = os.path.join(serverPath, f'{uId}', 'public_key.pem')
        with open(path, 'rb') as pubkey_file:
            public_key = pubkey_file.read()
            ca_private_key = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
            # public_key = serialization.load_pem_public_key(pubkey_file.read(), default_backend())
            print(ca_private_key)
            return ca_private_key
    except Exception as e:
        print('[CER_PPK] Exception at:', e)


def verify_certificate_1(cert, ppk):
    try:
        ppk.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.PKCS1v15(),  # Change padding as necessary
            cert.signature_hash_algorithm,
        )
        print("CSR verified successfully with the provided public key.")
        return True
    except Exception as e:
        print("Failed to verify CSR:", e)
        return False


def sign_certificate(aType, csr):
    try:
        with open("../server/CA/ca_private_key.pem", "rb") as key_file:
            ca_key = key_file.read()
            ca_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key)

        with open("../server/CA/ca_certificate.pem", "rb") as cert_file:
            ca_cert = cert_file.read()
            ca_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert)
        if aType.strip() == 'p':
            ca_constraints = "CA:TRUE"
        else:
            ca_constraints = "CA:FALSE"
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
        cert = crypto.X509()
        cert.set_subject(csr.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)
        cert.set_issuer(ca_certificate.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        # basic_constraints = ca_constraints
        # cert.add_extensions([
        #     crypto.X509Extension(b"basicConstraints", True, basic_constraints.encode()),
        #     crypto.X509Extension(
        #         b"subjectKeyIdentifier", False, b"hash", subject=cert
        #     ),
        # ])
        cert.sign(ca_private_key, "sha256")

        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    except Exception as e:
        print('[SIGN_CERT] Exception at:', e)


def save_signed_certificate(cId, cert):
    try:
        path = os.path.join(serverPath, f'{cId}', 'approved_certificate.pem')
        with open(path, "wb") as cert_file:
            cert_file.write(cert)
    except Exception as e:
        print('[SAVE_CER] Exception at:', e)


def certificate(c):
    try:
        status, loginInfo = login(c)
        if status:
            c.send(str(loginInfo[4]).encode())
            cert = c.recv(4096)
            if send_math_problem(c):
                signed_certificate = sign_certificate(loginInfo[4], cert)
                save_signed_certificate(loginInfo[0], signed_certificate)
                c.sendall(signed_certificate)
    except Exception as e:
        print('[CERTIFICATE] Exception at:', e)


def verify_certificate(path):
    with open(path, "rb") as cert_file:
        ca_cert_data = cert_file.read()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

    with open("../server/CA/ca_certificate.pem", "rb") as received_cert_file:
        received_cert_data = received_cert_file.read()
        received_cert = x509.load_pem_x509_certificate(received_cert_data, default_backend())

    subject = ca_cert.subject
    print("Subject Attributes:")
    for at in subject:
        print(f"{at.oid._name} : {at.value}")
    try:
        print('verifying .......')
        ca_cert.public_key().verify(
            received_cert.signature,
            received_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            received_cert.signature_hash_algorithm,
        )
        print("Verification successful: The received certificate is signed by the CA.")
    except Exception as e:
        print("Verification failed:", e)


def handle_connection(c):
    try:
        option = c.recv(1024).decode()
        if option.strip() == '1':
            status, loginInfo = login(c)
            if status:
                state = loginInfo[3]
                if state == 1:
                    c.send('1'.encode())
                    info(c, loginInfo)
                    generate_users_keys(loginInfo)
                    recv_cerKey(c, loginInfo[0])
                else:
                    pass
        elif option.strip() == '2':
            signup(c)
        elif option.strip() == '3':
            connect_and_recv(c)
        elif option.strip() == '4':
            verified_connection(c)
        elif option.strip() == '5':
            certificate(c)
        elif option.strip() == '6':
            status, loginInfo = login(c)
            if status:
                path = os.path.join(serverPath, f'{loginInfo[0]}', 'approved_certificate.pem')
                if os.path.exists(path):
                    verify_certificate(path)
        else:
            pass
        c.close()
    except Exception as e:
        print('[INPUT] Exception at:', e)


def start():
    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_connection, args=(client,)).start()
    except Exception as e:
        print('[CONNECTION] Exception at:', e)


if __name__ == "__main__":
    start()
