
import asyncio
import logging

from asyncua import Server, ua
from asyncua.crypto.permission_rules import User, UserRole
from asyncua.server.user_managers import UserManager


# ---------------- CONFIGURATION ----------------

ENDPOINT = "opc.tcp://127.0.0.1:4841/validation/server/"

USERNAME = "validation_user"
PASSWORD = "Validation@123"

CERTIFICATE = "server_cert.der"
PRIVATE_KEY = "server_key.pem"

NAMESPACE_URI = "urn:altaf:opcua:validation"


# ---------------- USER AUTHENTICATION ----------------

class ValidationUserManager(UserManager):

    def get_user(
        self,
        iserver,
        username=None,
        password=None,
        certificate=None
    ):

        if username == USERNAME and password == PASSWORD:
            logging.info("Authenticated user: %s", username)
            return User(role=UserRole.User, name=username)

        logging.warning("Authentication rejected for: %s", username)
        return None


# ---------------- SERVER ----------------

async def main():

    logging.basicConfig(level=logging.INFO)

    server = Server(user_manager=ValidationUserManager())

    await server.init()

    server.set_endpoint(ENDPOINT)
    server.set_server_name("Python OPC UA Validation Server")

    # Load server certificate and private key
    await server.load_certificate(CERTIFICATE)
    await server.load_private_key(PRIVATE_KEY)

    # Encrypted communication only
    server.set_security_policy([
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt
    ])

    # Username/password authentication only
    server.set_identity_tokens([
        ua.UserNameIdentityToken
    ])

    # Namespace
    idx = await server.register_namespace(NAMESPACE_URI)

    # ---------------- OBJECTS ----------------

    objects = server.nodes.objects

    device = await objects.add_object(
        idx, "ValidationDevice"
    )

    sensors = await device.add_object(
        idx, "Sensors"
    )

    controls = await device.add_object(
        idx, "Controls"
    )

    # ---------------- SENSOR VARIABLES ----------------

    temperature = await sensors.add_variable(
        idx, "Temperature", 25.0
    )

    rpm = await sensors.add_variable(
        idx, "RPM", 1200
    )

    moisture = await sensors.add_variable(
        idx, "Moisture", 45.0
    )

    # ---------------- CONTROL VARIABLES ----------------

    motor_running = await controls.add_variable(
        idx, "MotorRunning", True
    )

    temperature_setpoint = await controls.add_variable(
        idx, "TemperatureSetpoint", 30.0
    )

    await motor_running.set_writable()
    await temperature_setpoint.set_writable()

    # ---------------- SIMULATION ----------------

    async def update_sensors():

        current_temperature = 25.0
        current_rpm = 1200
        current_moisture = 45.0

        while True:

            current_temperature += 0.2
            current_rpm += 10
            current_moisture -= 0.1

            if current_temperature > 35:
                current_temperature = 25.0

            if current_rpm > 1800:
                current_rpm = 1200

            if current_moisture < 30:
                current_moisture = 45.0

            await temperature.write_value(
                current_temperature
            )

            await rpm.write_value(
                current_rpm
            )

            await moisture.write_value(
                current_moisture
            )

            await asyncio.sleep(2)

    # ---------------- START SERVER ----------------

    print("\n======================================")
    print(" PYTHON OPC UA VALIDATION SERVER")
    print("======================================")
    print("Endpoint:", ENDPOINT)
    print("Security: Basic256Sha256")
    print("Mode: SignAndEncrypt")
    print("Authentication: Username / Password")
    print("Username:", USERNAME)
    print("Password:", PASSWORD)
    print("Anonymous access: Disabled")
    print("======================================\n")

    async with server:

        await update_sensors()


if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("\nServer stopped.")
