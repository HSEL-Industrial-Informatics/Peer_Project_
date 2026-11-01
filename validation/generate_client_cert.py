import asyncio
from pathlib import Path
from asyncua import Client

async def main():
    client = Client("opc.tcp://127.0.0.1:4841/validation/server/")

    cert, key = await client.setup_self_signed_certificate(
        key_file=Path("client_key.pem"),
        cert_file=Path("client_cert.der"),
        subject_attrs={
            "countryName": "IN",
            "organizationName": "OPC UA Validation"
        },
        host_name="localhost"
    )

    print("\nSUCCESS")
    print("Certificate:", cert.resolve())
    print("Private key:", key.resolve())

asyncio.run(main())
