from datetime import datetime, timedelta
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if os.path.exists('../server'):
    os.mkdir('../server/CA')

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
    backend=default_backend()
)

caPrkPath = os.path.join('../server', 'CA', 'ca_private_key.pem')
# Save the CA private key to a file
with open(caPrkPath, "wb") as key_file:
    key_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "SY"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Damascus"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Damascus University"),
    x509.NameAttribute(NameOID.COMMON_NAME, "MyCA"),
])

issuer_key = private_key
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    datetime.utcnow() + timedelta(days=365)
).sign(issuer_key, hashes.SHA256(), default_backend())

caCerPath = os.path.join('../server', 'CA', 'ca_certificate.pem')
with open(caCerPath, "wb") as cert_file:
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
