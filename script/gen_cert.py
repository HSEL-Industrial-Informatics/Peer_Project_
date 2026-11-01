"""
reset_and_fix.py
================
Run this when:
- PC turned off during learning
- Getting certificate errors
- Connection keeps failing
- Event loop errors

This script cleans everything and starts fresh.
"""

import os
import asyncio
import datetime
import ipaddress
from pathlib import Path

CERT_DIR    = Path(
    r"C:\Users\faiza\OneDrive\Desktop"
    r"\opcua_project\certs")
CLIENT_CERT = CERT_DIR / "client_cert.pem"
CLIENT_KEY  = CERT_DIR / "client_key.pem"

APP_URI = "urn:example.org:FreeOpcUa:opcua-asyncio"

print("=" * 55)
print("OPC UA RESET AND FIX TOOL")
print("=" * 55)
print()

# ── Step 1: Delete old certificates ───────────────────────────────
print("Step 1: Cleaning old certificates...")
for f in [CLIENT_CERT, CLIENT_KEY]:
    if f.exists():
        f.unlink()
        print(f"  Deleted: {f.name}")
    else:
        print(f"  Not found: {f.name}")

# Also clean any cached asyncua files
cache_dirs = [
    Path.home() / ".asyncua",
    Path.home() / "AppData" / "Roaming" / "asyncua",
    Path(r"C:\Users\faiza\OneDrive\Desktop"
         r"\opcua_project") / "certificate-example.der",
]
for d in cache_dirs:
    if d.exists():
        if d.is_file():
            d.unlink()
            print(f"  Deleted cache: {d}")
        else:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
            print(f"  Deleted cache dir: {d}")

print("  Done cleaning")
print()

# ── Step 2: Generate fresh certificate ────────────────────────────
print("Step 2: Generating fresh certificate...")
CERT_DIR.mkdir(parents=True, exist_ok=True)

try:
    from cryptography import x509
    from cryptography.x509.oid import (
        NameOID, ExtendedKeyUsageOID)
    from cryptography.hazmat.primitives import (
        hashes, serialization)
    from cryptography.hazmat.primitives.asymmetric \
        import rsa

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, "HS Emden Leer"),
        x509.NameAttribute(
            NameOID.COMMON_NAME, "OpcUaClient"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow()
            + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(APP_URI),
                x509.DNSName("localhost"),
                x509.DNSName("Administrator"),
                x509.DNSName("ADMINISTRATOR"),
                x509.IPAddress(
                    ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(
                    ipaddress.IPv4Address("192.168.137.114")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(CLIENT_KEY, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat
            .TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    with open(CLIENT_CERT, "wb") as f:
        f.write(cert.public_bytes(
            serialization.Encoding.PEM))

    print(f"  Key  saved: {CLIENT_KEY}")
    print(f"  Cert saved: {CLIENT_CERT}")
    print("  Certificate generated successfully")

except ImportError:
    print("  ERROR: cryptography not installed")
    print("  Run: pip install cryptography")
    exit(1)
except Exception as e:
    print(f"  ERROR: {e}")
    exit(1)

print()

# ── Step 3: Test connection ────────────────────────────────────────
print("Step 3: Testing connection to Prosys...")
print("  (This will likely fail with cert error")
print("   first time — that is expected!)")
print()

SERVER_URL = (
    "opc.tcp://192.168.137.114:53530"
    "/OPCUA/SimulationServer"
)
USERNAME = "alt"
PASSWORD = "0000"


async def test_connection():
    from asyncua import Client, ua
    from asyncua.crypto.security_policies import (
        SecurityPolicyBasic256Sha256
    )
    try:
        client = Client(url=SERVER_URL)
        client.session_timeout        = 10000
        client.secure_channel_timeout = 5000

        await client.set_security(
            SecurityPolicyBasic256Sha256,
            certificate=str(CLIENT_CERT),
            private_key=str(CLIENT_KEY),
            mode=ua.MessageSecurityMode.SignAndEncrypt
        )
        client.set_user(USERNAME)
        client.set_password(PASSWORD)

        await client.connect()
        print("  CONNECTED SUCCESSFULLY!")
        await client.disconnect()
        return "SUCCESS"

    except Exception as e:
        err = str(e)
        if "BadCertificate" in err \
                or "certificate" in err.lower() \
                or "BadSecurity" in err:
            print(f"  Certificate not trusted yet: {err[:60]}")
            return "CERT_NOT_TRUSTED"
        elif "BadUserAccessDenied" in err \
                or "BadIdentityToken" in err:
            print(f"  Auth failed: {err[:60]}")
            return "AUTH_FAILED"
        elif "10061" in err or "refused" in err \
                or "timed out" in err \
                or "10060" in err:
            print(f"  Cannot reach server: {err[:60]}")
            return "NETWORK_ERROR"
        else:
            print(f"  Error: {err[:80]}")
            return "OTHER_ERROR"

# Use new event loop each time to avoid
# "event loop is closed" error after PC restart
result = asyncio.run(test_connection())

print()
print("=" * 55)

if result == "SUCCESS":
    print("EVERYTHING WORKS!")
    print("You can now run final_complete_learn.py")

elif result == "CERT_NOT_TRUSTED":
    print("CERTIFICATE NOT TRUSTED YET")
    print()
    print("Do this NOW on the Prosys laptop:")
    print()
    print("  1. Open Prosys OPC UA Simulation Server")
    print("  2. Click 'Certificates' tab at the top")
    print("  3. Look at the 'Rejected' section")
    print("  4. Find 'OpcUaClient' in the list")
    print("  5. Click on it to select it")
    print("  6. Click the 'Trust' button")
    print()
    print("Then run this script again to verify.")

elif result == "AUTH_FAILED":
    print("AUTHENTICATION FAILED")
    print()
    print(f"Username '{USERNAME}' or password '{PASSWORD}'")
    print("is wrong. Check in Prosys:")
    print("  Prosys → Users tab")
    print("  Verify the username and password")

elif result == "NETWORK_ERROR":
    print("CANNOT REACH SERVER")
    print()
    print("Check these:")
    print("  1. Both laptops on same WiFi network")
    print("  2. Open Command Prompt and run:")
    print("     ping 192.168.0.148")
    print("  3. If ping fails — network issue")
    print("  4. Check Windows Firewall on Prosys laptop")
    print("  5. Check Prosys is running (Status: Running)")

else:
    print("UNKNOWN ERROR — check output above")

print("=" * 55)