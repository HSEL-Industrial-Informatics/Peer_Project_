"""
harness.py
==========
OPC UA Protocol Harness
Server  : Prosys OPC UA Simulation Server
URL     : opc.tcp://192.168.0.148:53530/OPCUA/SimulationServer
Security: Basic256Sha256 Sign and Encrypt
Auth    : Username = alt / Password = 0000

FIXES in this version:
1. Certificate generated using correct asyncua API
2. Correct username (alt) and password (0000)
3. Certificate trust instructions for Prosys
"""

import asyncio
import subprocess
import sys
import os
from pathlib import Path
from asyncua import Client, ua
from asyncua.crypto.security_policies import (
    SecurityPolicyBasic256Sha256
)

# ── Configuration ──────────────────────────────────────────────────
SERVER_URL = (
    "opc.tcp://192.168.137.114:53530/OPCUA/SimulationServer"
)
USERNAME = "alt"
PASSWORD = "0000"

CERT_DIR    = Path(
    r"C:\Users\faiza\OneDrive\Desktop"
    r"\opcua_project\certs")
CLIENT_CERT = CERT_DIR / "client_cert.pem"
CLIENT_KEY  = CERT_DIR / "client_key.pem"


# ── Certificate generation ─────────────────────────────────────────
def generate_certificate():
    """
    Generate self-signed certificate using openssl.
    This method works with all asyncua versions.
    """
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    if CLIENT_CERT.exists() and CLIENT_KEY.exists():
        print("  [CERT] Certificate already exists")
        return True

    print("  [CERT] Generating certificate with openssl...")

    # Method 1 — try using openssl command
    try:
        cmd = [
            "openssl", "req", "-x509",
            "-newkey", "rsa:2048",
            "-keyout", str(CLIENT_KEY),
            "-out", str(CLIENT_CERT),
            "-days", "365",
            "-nodes",
            "-subj",
            "/C=DE/ST=Niedersachsen/L=Emden"
            "/O=HSEmdenLeer/CN=OpcUaClient",
            "-addext",
            "subjectAltName=URI:urn:opcua:python:client"
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        if result.returncode == 0 \
                and CLIENT_CERT.exists():
            print("  [CERT] Certificate generated with openssl")
            return True
        else:
            print(f"  [CERT] openssl failed: {result.stderr}")
    except FileNotFoundError:
        print("  [CERT] openssl not found, trying Python method...")

    # Method 2 — try asyncua built-in
    try:
        from asyncua.crypto.cert_gen import (
            setup_self_signed_certificate
        )
        import inspect
        sig = inspect.signature(
            setup_self_signed_certificate)
        params = list(sig.parameters.keys())
        print(f"  [CERT] asyncua cert_gen params: {params}")

        # Try different parameter combinations
        if 'certificate_file' in params:
            asyncio.get_event_loop().run_until_complete(
                setup_self_signed_certificate(
                    key_file=CLIENT_KEY,
                    certificate_file=CLIENT_CERT,
                    app_uri="urn:opcua:python:client",
                    host_name="localhost",
                ))
        elif 'cert_file' in params:
            asyncio.get_event_loop().run_until_complete(
                setup_self_signed_certificate(
                    key_file=CLIENT_KEY,
                    cert_file=CLIENT_CERT,
                    app_uri="urn:opcua:python:client",
                    host_name="localhost",
                ))
        else:
            # Try positional
            asyncio.get_event_loop().run_until_complete(
                setup_self_signed_certificate(
                    CLIENT_KEY,
                    CLIENT_CERT,
                    "urn:opcua:python:client",
                    "localhost",
                ))

        if CLIENT_CERT.exists():
            print("  [CERT] Certificate generated with asyncua")
            return True
    except Exception as e:
        print(f"  [CERT] asyncua method failed: {e}")

    # Method 3 — use cryptography library directly
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import (
            hashes, serialization
        )
        from cryptography.hazmat.primitives.asymmetric \
            import rsa
        import datetime

        print("  [CERT] Using cryptography library...")

        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(
                NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME,
                "Niedersachsen"),
            x509.NameAttribute(
                NameOID.LOCALITY_NAME, "Emden"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "HS Emden Leer"),
            x509.NameAttribute(
                NameOID.COMMON_NAME, "OpcUaClient"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(
                x509.random_serial_number())
            .not_valid_before(
                datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow()
                + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(
                        "urn:opcua:python:client"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(
                    ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Save private key
        with open(CLIENT_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat
                .TraditionalOpenSSL,
                encryption_algorithm=serialization
                .NoEncryption(),
            ))

        # Save certificate
        with open(CLIENT_CERT, "wb") as f:
            f.write(cert.public_bytes(
                serialization.Encoding.PEM))

        print("  [CERT] Certificate generated with"
              " cryptography library")
        return True

    except ImportError:
        print("  [CERT] cryptography library not found")
        print("  Run: pip install cryptography")
    except Exception as e:
        print(f"  [CERT] cryptography method failed: {e}")

    return False


# ── Harness class ──────────────────────────────────────────────────
class OpcUaHarness:
    """
    Maps abstract symbols to real encrypted OPC UA messages.
    Uses Basic256Sha256 Sign and Encrypt with
    username/password authentication.
    """

    def __init__(self):
        self.client       = None
        self.node         = None
        self.subscription = None
        self.monitored    = None
        self.connected    = False

    async def _setup_client(self):
        """Create and configure encrypted client"""
        self.client = Client(url=SERVER_URL)
        self.client.session_timeout        = 30000
        self.client.secure_channel_timeout = 10000

        # Apply Basic256Sha256 encryption
        await self.client.set_security(
            SecurityPolicyBasic256Sha256,
            certificate=str(CLIENT_CERT),
            private_key=str(CLIENT_KEY),
            mode=ua.MessageSecurityMode.SignAndEncrypt
        )

        # Set username and password
        self.client.set_user(USERNAME)
        self.client.set_password(PASSWORD)

    async def _find_node(self):
        """Find Counter node in Simulation folder"""
        try:
            objects  = self.client.nodes.objects
            children = await objects.get_children()
            for child in children:
                name = str(
                    await child.read_browse_name())
                if "Simulation" in name:
                    kids = await child.get_children()
                    for k in kids:
                        kn = str(
                            await k.read_browse_name())
                        if "Counter" in kn:
                            self.node = k
                            print(
                                f"  [HARNESS] Node: {kn}")
                            return
                    if kids:
                        self.node = kids[0]
                        n = str(await self.node
                                .read_browse_name())
                        print(f"  [HARNESS] Node: {n}")
                        return
            # Fallback to ServerTime
            self.node = self.client.get_node("i=2258")
            print("  [HARNESS] Using fallback: ServerTime")
        except Exception as e:
            print(f"  [HARNESS] Node error: {e}")
            self.node = self.client.get_node("i=2258")

    async def connect(self):
        if self.connected:
            return "ALREADY_CONNECTED"
        try:
            await self._setup_client()
            await self.client.connect()
            self.connected = True
            print("  [HARNESS] Connected — encrypted")
            await self._find_node()
            return "CONNECT_OK"
        except Exception as e:
            self.connected = False
            err = str(e)
            print(f"  [HARNESS] Connect error: {err[:60]}")
            if "BadUserAccessDenied" in err \
                    or "BadIdentityTokenRejected" in err:
                return "CONNECT_AUTH_FAILED"
            if "certificate" in err.lower() \
                    or "BadSecurity" in err \
                    or "BadCertificate" in err:
                return "CONNECT_CERT_ERROR"
            if "No such file" in err:
                return "CONNECT_NO_CERT"
            return "CONNECT_ERROR"

    async def disconnect(self):
        if not self.connected:
            return "NOT_CONNECTED"
        try:
            if self.monitored and self.subscription:
                try:
                    await self.subscription.unsubscribe(
                        self.monitored)
                except Exception:
                    pass
                self.monitored = None
            if self.subscription:
                try:
                    await self.subscription.delete()
                except Exception:
                    pass
                self.subscription = None
            await self.client.disconnect()
            self.connected = False
            self.client    = None
            self.node      = None
            print("  [HARNESS] Disconnected")
            return "DISCONNECT_OK"
        except Exception:
            self.connected = False
            return "DISCONNECT_ERROR"

    async def query(self, symbol):
        """Send one symbol to server, return response"""

        if symbol == "CONNECT":
            return await self.connect()

        if symbol == "DISCONNECT":
            return await self.disconnect()

        if not self.connected:
            return "NOT_CONNECTED"

        try:
            if symbol == "READ":
                await self.node.read_value()
                return "READ_OK"

            elif symbol == "WRITE":
                try:
                    val = await self.node.read_value()
                    await self.node.write_value(val)
                    return "WRITE_OK"
                except ua.UaStatusCodeError as e:
                    code = str(e)
                    if "BadUserAccessDenied" in code:
                        return "WRITE_ACCESS_DENIED"
                    return "WRITE_REJECTED"

            elif symbol == "BROWSE":
                await self.client.nodes.objects\
                    .get_children()
                return "BROWSE_OK"

            elif symbol == "BROWSE_DEEP":
                count   = 0
                objects = self.client.nodes.objects
                for child in await objects.get_children():
                    name = str(
                        await child.read_browse_name())
                    if "Simulation" in name:
                        kids  = await child.get_children()
                        count = len(kids)
                        break
                if count >= 5:
                    return "BROWSE_DEEP_OK"
                elif count > 0:
                    return "BROWSE_DEEP_PARTIAL"
                else:
                    return "BROWSE_DEEP_EMPTY"

            elif symbol == "GET_STATUS":
                status = self.client.get_node("i=2259")
                await status.read_value()
                return "STATUS_OK"

            elif symbol == "CREATE_SUB":
                if self.subscription:
                    return "SUB_EXISTS"
                self.subscription = await \
                    self.client.create_subscription(
                        500, None)
                return "CREATE_SUB_OK"

            elif symbol == "DELETE_SUB":
                if not self.subscription:
                    return "NO_SUB"
                if self.monitored:
                    try:
                        await self.subscription\
                            .unsubscribe(self.monitored)
                    except Exception:
                        pass
                    self.monitored = None
                await self.subscription.delete()
                self.subscription = None
                return "DELETE_SUB_OK"

            elif symbol == "CREATE_MON":
                if not self.subscription:
                    return "NO_SUB"
                if self.monitored:
                    return "MON_EXISTS"
                self.monitored = await \
                    self.subscription\
                    .subscribe_data_change(self.node)
                return "CREATE_MON_OK"

            elif symbol == "DELETE_MON":
                if not self.subscription:
                    return "NO_SUB"
                if not self.monitored:
                    return "NO_MON"
                await self.subscription.unsubscribe(
                    self.monitored)
                self.monitored = None
                return "DELETE_MON_OK"

        except Exception as e:
            self.connected = False
            return "ERROR"

        return "UNKNOWN"


# ── Validation tests ───────────────────────────────────────────────
async def test_harness():
    # Step 1 — generate certificate
    print("Step 1: Generating certificate...")
    ok = generate_certificate()
    if not ok:
        print()
        print("ERROR: Could not generate certificate!")
        print("Install cryptography: pip install cryptography")
        return

    print()
    print("=" * 55)
    print("IMPORTANT — Before running tests:")
    print()
    print("1. Open Prosys on the other laptop")
    print("2. Click 'Certificates' tab")
    print("3. Look in 'Rejected' section")
    print("4. You should see 'OpcUaClient' certificate")
    print("5. Click it → click 'Trust' button")
    print("6. THEN run this script again")
    print()
    print("If Rejected section is empty — run tests")
    print("once first, then check Prosys certificates")
    print("=" * 55)
    print()
    input("Press Enter when certificate is trusted in Prosys...")
    print()

    print("=" * 55)
    print("HARNESS VALIDATION")
    print(f"Server  : {SERVER_URL}")
    print("Security: Basic256Sha256 Sign and Encrypt")
    print(f"Auth    : {USERNAME} / {PASSWORD}")
    print("=" * 55)
    print()

    h      = OpcUaHarness()
    passed = 0
    failed = 0

    def check(name, result, expected_contains):
        nonlocal passed, failed
        ok = any(e in str(result)
                 for e in expected_contains)
        status = "PASSED" if ok else "FAILED"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  {name:35} → {str(result):30} {status}")
        return ok

    check("CONNECT",
          await h.query("CONNECT"),
          ["CONNECT_OK"])

    check("CONNECT again (should be ALREADY)",
          await h.query("CONNECT"),
          ["ALREADY_CONNECTED"])

    check("READ",
          await h.query("READ"),
          ["READ_OK"])

    check("WRITE",
          await h.query("WRITE"),
          ["WRITE_OK", "WRITE_REJECTED",
           "WRITE_ACCESS_DENIED"])

    check("BROWSE",
          await h.query("BROWSE"),
          ["BROWSE_OK"])

    check("BROWSE_DEEP",
          await h.query("BROWSE_DEEP"),
          ["BROWSE_DEEP_OK", "BROWSE_DEEP_PARTIAL",
           "BROWSE_DEEP_EMPTY"])

    check("GET_STATUS",
          await h.query("GET_STATUS"),
          ["STATUS_OK"])

    check("CREATE_SUB",
          await h.query("CREATE_SUB"),
          ["CREATE_SUB_OK"])

    check("CREATE_SUB again (duplicate)",
          await h.query("CREATE_SUB"),
          ["SUB_EXISTS"])

    check("CREATE_MON",
          await h.query("CREATE_MON"),
          ["CREATE_MON_OK"])

    check("CREATE_MON again (duplicate)",
          await h.query("CREATE_MON"),
          ["MON_EXISTS"])

    check("DELETE_MON",
          await h.query("DELETE_MON"),
          ["DELETE_MON_OK"])

    check("DELETE_MON again (no mon)",
          await h.query("DELETE_MON"),
          ["NO_MON"])

    check("DELETE_SUB",
          await h.query("DELETE_SUB"),
          ["DELETE_SUB_OK"])

    check("DELETE_SUB again (no sub)",
          await h.query("DELETE_SUB"),
          ["NO_SUB"])

    check("DISCONNECT",
          await h.query("DISCONNECT"),
          ["DISCONNECT_OK"])

    check("READ after disconnect",
          await h.query("READ"),
          ["NOT_CONNECTED"])

    check("WRITE after disconnect",
          await h.query("WRITE"),
          ["NOT_CONNECTED"])

    print()
    print("=" * 55)
    print(f"Results: {passed}/{passed+failed} passed")
    if failed == 0:
        print("ALL PASSED — ready for L* learning!")
    else:
        print(f"{failed} tests FAILED")
        print()
        print("If CONNECT_CERT_ERROR:")
        print("  → Trust cert in Prosys Certificates tab")
        print()
        print("If CONNECT_AUTH_FAILED:")
        print(f"  → Check username={USERNAME}"
              f" password={PASSWORD}")
        print("  → Check Prosys Users tab")
        print()
        print("If CONNECT_ERROR (network):")
        print("  → Check both laptops on same WiFi")
        print("  → Ping 192.168.0.148 from terminal")
        print("  → Check Prosys firewall settings")
    print("=" * 55)


if __name__ == "__main__":
    asyncio.run(test_harness())