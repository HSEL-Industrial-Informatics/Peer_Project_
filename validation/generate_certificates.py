from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption
)
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

# Generate private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OPCUA Validation"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Python OPC UA Server"),
])

now = datetime.now(timezone.utc)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ip_address("127.0.0.1")),
            x509.IPAddress(ip_address("192.168.0.148")),
        ]),
        critical=False
    )
    .add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH
        ]),
        critical=False
    )
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    .sign(private_key=key, algorithm=hashes.SHA256())
)

with open("server_key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ))

with open("server_cert.der", "wb") as f:
    f.write(cert.public_bytes(Encoding.DER))

print("Server certificate and private key generated.")