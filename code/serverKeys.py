import gnupg
import hashlib


def generate_server_keys():
    gpg = gnupg.GPG(gnupghome='C:/Users/abdul/AppData/Roaming/gnupg', gpgbinary='c:/Program Files (x86)/GnuPG/bin/gpg')

    gpg.encoding = 'utf-8'

    server_passphrase = '2048'

    hashed_password = hashlib.sha256(server_passphrase.encode()).hexdigest()

    with open('../server/key_password/server_passphrase.pwd', 'w') as public_file:
        public_file.write(hashed_password)

    input_data = gpg.gen_key_input(
        name_email='server',
        passphrase=server_passphrase,
        key_type='RSA',
        key_length=1024
    )

    key = gpg.gen_key(input_data)
    public_key = gpg.export_keys(key.fingerprint)

    with open('../server/key_password/server_public_key.asc', 'w') as public_file:
        public_file.write(public_key)
