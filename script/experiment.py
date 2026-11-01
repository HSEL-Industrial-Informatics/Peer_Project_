
"""
experiment.py
=========================================================
OPC UA State Machine Learning — Python Server Validation

Server:
    opc.tcp://127.0.0.1:4841/validation/server/

Security:
    Basic256Sha256
    SignAndEncrypt
    Client certificate + server certificate
    Username/password authentication

Learning:
    AALpy L* algorithm
    Mealy machine
    RandomWalkEqOracle

Target hierarchy:
    Objects
      └── ValidationDevice
            ├── Sensors
            │     ├── Temperature
            │     ├── RPM
            │     └── Moisture
            └── Controls
                  ├── MotorRunning
                  └── TemperatureSetpoint

Results are saved separately from Prosys experiments.
"""

import asyncio
import logging
import os
import time
from pathlib import Path

from asyncua import Client, ua
from asyncua.crypto.security_policies import (
    SecurityPolicyBasic256Sha256
)

from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWalkEqOracle
from aalpy.SULs import SUL


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(
    r"C:\Users\faiza\OneDrive\Desktop\opcua_project"
)

VALIDATION_DIR = BASE_DIR / "validation"

SERVER_URL = (
    "opc.tcp://127.0.0.1:4841/validation/server/"
)

USERNAME = "validation_user"
PASSWORD = "Validation@123"

CLIENT_CERT = VALIDATION_DIR / "client_cert.der"
CLIENT_KEY = VALIDATION_DIR / "client_key.pem"
SERVER_CERT = VALIDATION_DIR / "server_cert.der"

RESULTS = VALIDATION_DIR / "results"

SLEEP_AFTER_DISCONNECT = 1.0
SLEEP_AFTER_CREATE_SUB = 2.0
SLEEP_AFTER_CREATE_MON = 1.0
SLEEP_BETWEEN_OPS = 0.1

MAX_RETRIES = 3
RETRY_SLEEP = 2.0

CONNECTION_TIMEOUT = 15.0
OPERATION_TIMEOUT = 8.0


# =========================================================
# LOGGING
# =========================================================

logging.getLogger("asyncua").setLevel(logging.CRITICAL)
logging.getLogger("asyncua.client").setLevel(logging.CRITICAL)
logging.getLogger(
    "asyncua.common.subscription"
).setLevel(logging.CRITICAL)


# =========================================================
# SYSTEM UNDER LEARNING
# =========================================================

class AutoReconnectSUL(SUL):

    def __init__(self):
        super().__init__()

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        self.client = None

        self.node = None
        self.write_node = None

        self.subscription = None
        self.monitored = None

        self.connected = False
        self.browse_done = False
        self.has_sub = False
        self.has_mon = False

        print("Security: Basic256Sha256")
        print("Message Security Mode: SignAndEncrypt")
        print("Authentication: Username/password")

    # -----------------------------------------------------
    # AALPY INTERFACE
    # -----------------------------------------------------

    def pre(self):
        self.loop.run_until_complete(self._full_reset())
        time.sleep(SLEEP_AFTER_DISCONNECT)

    def post(self):
        pass

    def step(self, symbol):
        result = self.loop.run_until_complete(
            self._step(symbol)
        )

        time.sleep(SLEEP_BETWEEN_OPS)
        return result

    def _state_code(self):
        b = "1" if self.browse_done else "0"
        s = "1" if self.has_sub else "0"
        m = "1" if self.has_mon else "0"

        return f"STATE_{b}{s}{m}"

    # -----------------------------------------------------
    # SECURITY FILE CHECK
    # -----------------------------------------------------

    def _check_certificates(self):

        required = [
            CLIENT_CERT,
            CLIENT_KEY,
            SERVER_CERT
        ]

        for path in required:
            if not path.is_file():
                raise FileNotFoundError(
                    f"Certificate file not found: {path}"
                )

    # -----------------------------------------------------
    # CONNECTION CHECK
    # -----------------------------------------------------

    async def _safe_ping(self):

        if not self.connected or self.client is None:
            self.connected = False
            return False

        try:
            node = self.client.get_node("i=2258")

            await asyncio.wait_for(
                node.read_value(),
                timeout=4.0
            )

            return True

        except Exception:
            self.connected = False
            return False

    # -----------------------------------------------------
    # NODE DISCOVERY
    # -----------------------------------------------------

    async def _find_child(self, parent, name):

        children = await asyncio.wait_for(
            parent.get_children(),
            timeout=OPERATION_TIMEOUT
        )

        for child in children:
            browse_name = await child.read_browse_name()

            if browse_name.Name == name:
                return child

        return None

    async def _find_nodes(self):

        objects = self.client.nodes.objects

        device = await self._find_child(
            objects, "ValidationDevice"
        )

        if device is None:
            raise RuntimeError(
                "ValidationDevice not found"
            )

        sensors = await self._find_child(
            device, "Sensors"
        )

        controls = await self._find_child(
            device, "Controls"
        )

        if sensors is None:
            raise RuntimeError("Sensors object not found")

        if controls is None:
            raise RuntimeError("Controls object not found")

        temperature = await self._find_child(
            sensors, "Temperature"
        )

        temperature_setpoint = await self._find_child(
            controls, "TemperatureSetpoint"
        )

        if temperature is None:
            raise RuntimeError("Temperature node not found")

        if temperature_setpoint is None:
            raise RuntimeError(
                "TemperatureSetpoint node not found"
            )

        # READ and monitoring use the sensor.
        # WRITE uses the writable setpoint.
        await temperature.read_value()
        await temperature_setpoint.read_value()

        return temperature, temperature_setpoint

    # -----------------------------------------------------
    # FULL RESET
    # -----------------------------------------------------

    async def _full_reset(self):

        if self.monitored is not None and self.subscription:
            try:
                await asyncio.wait_for(
                    self.subscription.unsubscribe(
                        self.monitored
                    ),
                    timeout=3.0
                )
            except Exception:
                pass

        self.monitored = None

        if self.subscription is not None:
            try:
                await asyncio.wait_for(
                    self.subscription.delete(),
                    timeout=3.0
                )
            except Exception:
                pass

        self.subscription = None

        if self.client is not None:
            try:
                await asyncio.wait_for(
                    self.client.disconnect(),
                    timeout=3.0
                )
            except Exception:
                pass

        self.client = None
        self.node = None
        self.write_node = None

        self.connected = False
        self.browse_done = False
        self.has_sub = False
        self.has_mon = False

    # -----------------------------------------------------
    # SECURE CONNECTION
    # -----------------------------------------------------

    async def _raw_connect(self):

        client = None

        try:
            client = Client(url=SERVER_URL)

            client.session_timeout = 30000
            client.secure_channel_timeout = 10000

            # Configure certificate-based encryption
            # BEFORE connecting.

            await client.set_security(
                SecurityPolicyBasic256Sha256,
                str(CLIENT_CERT),
                str(CLIENT_KEY),
                server_certificate=str(SERVER_CERT),
                mode=ua.MessageSecurityMode.SignAndEncrypt
            )

            # Username/password authentication
            client.set_user(USERNAME)
            client.set_password(PASSWORD)

            await asyncio.wait_for(
                client.connect(),
                timeout=CONNECTION_TIMEOUT
            )

            # Verify server session
            status_node = client.get_node("i=2258")

            await asyncio.wait_for(
                status_node.read_value(),
                timeout=OPERATION_TIMEOUT
            )

            self.client = client

            read_node, write_node = await self._find_nodes()

            self.node = read_node
            self.write_node = write_node

            return True, client

        except Exception as exc:

            logging.debug(
                "Secure connection failed: %s",
                exc
            )

            if client is not None:
                try:
                    await client.disconnect()
                except Exception:
                    pass

            self.client = None

            return False, None

    # -----------------------------------------------------
    # CONNECT
    # -----------------------------------------------------

    async def _connect_fresh(self):

        for attempt in range(MAX_RETRIES):

            if attempt > 0:
                await asyncio.sleep(RETRY_SLEEP)

            ok, client = await self._raw_connect()

            if ok:

                self.client = client
                self.connected = True

                self.browse_done = False
                self.has_sub = False
                self.has_mon = False

                self.subscription = None
                self.monitored = None

                return "CONNECT_OK"

        return "CONNECT_ERROR"

    # -----------------------------------------------------
    # RECONNECT AND RESTORE RESOURCES
    # -----------------------------------------------------

    async def _reconnect_preserve_state(self):

        had_sub = self.has_sub
        had_mon = self.has_mon
        had_browse = self.browse_done

        old_client = self.client

        self.client = None
        self.node = None
        self.write_node = None

        self.subscription = None
        self.monitored = None

        self.connected = False

        if old_client is not None:
            try:
                await asyncio.wait_for(
                    old_client.disconnect(),
                    timeout=3.0
                )
            except Exception:
                pass

        await asyncio.sleep(RETRY_SLEEP)

        ok, client = await self._raw_connect()

        if not ok:
            self.has_sub = False
            self.has_mon = False
            self.browse_done = False
            return False

        self.client = client
        self.connected = True
        self.browse_done = had_browse

        if had_sub:
            try:
                self.subscription = await asyncio.wait_for(
                    self.client.create_subscription(
                        1000, None
                    ),
                    timeout=10.0
                )

                self.has_sub = True

                await asyncio.sleep(0.5)

                if had_mon:
                    self.monitored = await asyncio.wait_for(
                        self.subscription.subscribe_data_change(
                            self.node
                        ),
                        timeout=10.0
                    )

                    self.has_mon = True

            except Exception as exc:

                logging.debug(
                    "Subscription restoration failed: %s",
                    exc
                )

                self.subscription = None
                self.monitored = None

                self.has_sub = False
                self.has_mon = False

        else:
            self.has_sub = False
            self.has_mon = False

        return True

    # -----------------------------------------------------
    # INPUT SYMBOL EXECUTION
    # -----------------------------------------------------

    async def _step(self, symbol):

        try:

            # CONNECT
            if symbol == "CONNECT":

                if self.connected:

                    if await self._safe_ping():
                        return "ALREADY_CONNECTED"

                    await self._full_reset()

                return await self._connect_fresh()

            # DISCONNECT
            if symbol == "DISCONNECT":

                if not self.connected:
                    return "NOT_CONNECTED"

                await self._full_reset()
                return "DISCONNECT_OK"

            # QUERY_STATE
            if symbol == "QUERY_STATE":

                if not self.connected:
                    return "DISC"

                if not await self._safe_ping():

                    ok = await self._reconnect_preserve_state()

                    if not ok:
                        return "DISC"

                return self._state_code()

            # Remaining operations need a live session.
            if not await self._safe_ping():

                self.connected = False
                return "NOT_CONNECTED"

            # READ
            if symbol == "READ":

                try:
                    await asyncio.wait_for(
                        self.node.read_value(),
                        timeout=OPERATION_TIMEOUT
                    )

                    return "READ_OK"

                except ua.UaStatusCodeError as exc:

                    if "BadUserAccessDenied" in str(exc):
                        return "READ_ACCESS_DENIED"

                    return "READ_ERROR"

                except Exception:
                    return "READ_ERROR"

            # WRITE
            if symbol == "WRITE":

                try:
                    value = await asyncio.wait_for(
                        self.write_node.read_value(),
                        timeout=OPERATION_TIMEOUT
                    )

                    await asyncio.wait_for(
                        self.write_node.write_value(value),
                        timeout=OPERATION_TIMEOUT
                    )

                    return "WRITE_OK"

                except ua.UaStatusCodeError as exc:

                    if "BadUserAccessDenied" in str(exc):
                        return "WRITE_ACCESS_DENIED"

                    return "WRITE_REJECTED"

                except Exception:
                    return "WRITE_ERROR"

            # BROWSE
            if symbol == "BROWSE":

                try:
                    await self.client.nodes.objects.get_children()

                    self.browse_done = True
                    return "BROWSE_OK"

                except Exception:
                    return "BROWSE_ERROR"

            # BROWSE_DEEP
            if symbol == "BROWSE_DEEP":

                try:

                    objects = self.client.nodes.objects

                    device = await self._find_child(
                        objects, "ValidationDevice"
                    )

                    if device is None:
                        return "BROWSE_DEEP_EMPTY"

                    groups = await device.get_children()

                    count = 0

                    for group in groups:
                        children = await group.get_children()
                        count += len(children)

                    self.browse_done = True

                    if count >= 5:
                        return "BROWSE_DEEP_OK"

                    if count > 0:
                        return "BROWSE_DEEP_PARTIAL"

                    return "BROWSE_DEEP_EMPTY"

                except Exception:
                    return "BROWSE_DEEP_ERROR"

            # GET_STATUS
            if symbol == "GET_STATUS":

                try:
                    status_node = self.client.get_node("i=2259")

                    await asyncio.wait_for(
                        status_node.read_value(),
                        timeout=OPERATION_TIMEOUT
                    )

                    return "STATUS_OK"

                except Exception:
                    return "STATUS_ERROR"

            # CREATE_SUB
            if symbol == "CREATE_SUB":

                if self.subscription is not None:
                    return "SUB_EXISTS"

                try:

                    self.subscription = await asyncio.wait_for(
                        self.client.create_subscription(
                            1000, None
                        ),
                        timeout=10.0
                    )

                    self.has_sub = True

                    await asyncio.sleep(
                        SLEEP_AFTER_CREATE_SUB
                    )

                    if not await self._safe_ping():

                        ok = await self._reconnect_preserve_state()

                        if not ok:
                            return "CREATE_SUB_ERROR"

                    return "CREATE_SUB_OK"

                except Exception as exc:

                    logging.debug(
                        "Create subscription failed: %s",
                        exc
                    )

                    self.subscription = None
                    self.monitored = None

                    self.has_sub = False
                    self.has_mon = False

                    return "CREATE_SUB_ERROR"

            # DELETE_SUB
            if symbol == "DELETE_SUB":

                if self.subscription is None:
                    return "NO_SUB"

                try:

                    if self.monitored is not None:

                        await asyncio.wait_for(
                            self.subscription.unsubscribe(
                                self.monitored
                            ),
                            timeout=5.0
                        )

                        self.monitored = None
                        self.has_mon = False

                    await asyncio.wait_for(
                        self.subscription.delete(),
                        timeout=5.0
                    )

                    self.subscription = None
                    self.has_sub = False

                    return "DELETE_SUB_OK"

                except Exception:
                    return "DELETE_SUB_ERROR"

            # CREATE_MON
            if symbol == "CREATE_MON":

                if self.subscription is None:
                    return "NO_SUB"

                if self.monitored is not None:
                    return "MON_EXISTS"

                try:

                    self.monitored = await asyncio.wait_for(
                        self.subscription.subscribe_data_change(
                            self.node
                        ),
                        timeout=10.0
                    )

                    self.has_mon = True

                    await asyncio.sleep(
                        SLEEP_AFTER_CREATE_MON
                    )

                    return "CREATE_MON_OK"

                except Exception:

                    self.monitored = None
                    self.has_mon = False

                    return "CREATE_MON_ERROR"

            # DELETE_MON
            if symbol == "DELETE_MON":

                if self.subscription is None:
                    return "NO_SUB"

                if self.monitored is None:
                    return "NO_MON"

                try:

                    await asyncio.wait_for(
                        self.subscription.unsubscribe(
                            self.monitored
                        ),
                        timeout=5.0
                    )

                    self.monitored = None
                    self.has_mon = False

                    return "DELETE_MON_OK"

                except Exception:
                    return "DELETE_MON_ERROR"

            return "UNKNOWN"

        except Exception as exc:

            logging.debug(
                "Unexpected error for %s: %s",
                symbol,
                exc
            )

            self.connected = False
            return "ERROR"


# =========================================================
# MODEL EXTRACTION
# =========================================================

def extract_model(model, alphabet):

    rows = []

    for state in model.states:

        output = getattr(state, "output_fun", {})

        for symbol in alphabet:

            result = output.get(symbol, "?")
            transition = state.transitions.get(symbol)

            next_state = (
                getattr(transition, "state_id", "?")
                if transition else "?"
            )

            rows.append(
                (
                    state.state_id,
                    symbol,
                    result,
                    next_state
                )
            )

    return rows


# =========================================================
# STATE LABELS
# =========================================================

def label_states(model):

    state_map = {

        "DISC": (
            "Disconnected",
            "#FFD54F",
            "#F57F17"
        ),

        "STATE_000": (
            "Connected\\n(fresh session)",
            "#B3E5FC",
            "#0277BD"
        ),

        "STATE_100": (
            "Connected\\n+Browse",
            "#4FC3F7",
            "#0277BD"
        ),

        "STATE_010": (
            "Connected\\n+Subscribed",
            "#80DEEA",
            "#00838F"
        ),

        "STATE_110": (
            "Connected\\n+Browse+Sub",
            "#4DB6AC",
            "#00695C"
        ),

        "STATE_011": (
            "Connected\\n+Sub+Monitor",
            "#80CBC4",
            "#00695C"
        ),

        "STATE_111": (
            "Connected\\n+Browse+Sub+Mon",
            "#26A69A",
            "#004D40"
        ),

        "STATE_001": (
            "Connected\\n+Monitor",
            "#B2EBF2",
            "#006064"
        ),

        "STATE_101": (
            "Connected\\n+Browse+Mon",
            "#00BCD4",
            "#006064"
        )
    }

    labels = {}

    for state in model.states:

        output = getattr(state, "output_fun", {})
        sid = state.state_id

        query_state = output.get(
            "QUERY_STATE",
            "DISC"
        )

        if state == model.initial_state:
            query_state = "DISC"

        if query_state in state_map:

            description, fill, stroke = state_map[
                query_state
            ]

            labels[sid] = (
                f"{sid}\\n{description}",
                fill,
                stroke
            )

        else:

            labels[sid] = (
                f"{sid}\\n{query_state}",
                "#CE93D8",
                "#6A1B9A"
            )

    return labels


# =========================================================
# DOT GRAPH GENERATION
# =========================================================

def build_dot(model, alphabet, rows, labels):

    colors = {

        "CONNECT_OK": "#2E7D32",
        "DISCONNECT_OK": "#1565C0",
        "READ_OK": "#1B5E20",
        "WRITE_OK": "#E65100",
        "WRITE_REJECTED": "#B71C1C",
        "WRITE_ACCESS_DENIED": "#880E4F",
        "BROWSE_OK": "#7B1FA2",
        "BROWSE_DEEP_OK": "#6A1B9A",
        "STATUS_OK": "#004D40",
        "CREATE_SUB_OK": "#00695C",
        "DELETE_SUB_OK": "#4527A0",
        "CREATE_MON_OK": "#1A237E",
        "DELETE_MON_OK": "#880E4F",
        "NOT_CONNECTED": "#C62828",
        "ALREADY_CONNECTED": "#BF360C",
        "SUB_EXISTS": "#E65100",
        "MON_EXISTS": "#E65100",
        "NO_SUB": "#C62828",
        "NO_MON": "#C62828",
        "DISC": "#C62828"
    }

    lines = [

        'digraph "OPC_UA_Python_Validation" {',

        "    rankdir=LR;",

        '    bgcolor="white";',

        '    fontname="Arial";',

        '    label="OPC UA Learned State Machine\\n'
        'Security: Basic256Sha256 SignAndEncrypt\\n'
        'Authentication: Username/password\\n'
        'Algorithm: L* (AALpy)";',

        '    labelloc="t";',

        "    fontsize=13;",

        '    node [fontname="Arial", fontsize=10,',

        "          style=filled, shape=circle,",

        "          width=1.9, height=1.9];",

        '    edge [fontname="Arial", fontsize=7];',

        "",

        '    __start [shape=none, label="", width=0, height=0];',

        f'    __start -> {model.initial_state.state_id} '
        '[label="start"];',

        ""
    ]

    for state in model.states:

        sid = state.state_id

        label, fill, stroke = labels.get(
            sid,
            (str(sid), "#E0E0E0", "#9E9E9E")
        )

        lines.append(
            f'    {sid} [label="{label}", '
            f'fillcolor="{fill}", color="{stroke}", '
            f'penwidth=2.5];'
        )

    lines.append("")

    from collections import defaultdict

    grouped = defaultdict(list)

    for source, symbol, output, target in rows:

        grouped[(source, target)].append(
            f"{symbol}/{output}"
        )

    for (source, target), symbols in grouped.items():

        first_output = next(
            (
                output
                for src, symbol, output, dst in rows
                if src == source and dst == target
            ),
            ""
        )

        color = colors.get(first_output, "#666666")

        label = "\\n".join(symbols)

        style = (
            "dashed"
            if source == target
            else "solid"
        )

        width = (
            "1.0"
            if source == target
            else "2.5"
        )

        lines.append(
            f'    {source} -> {target} '
            f'[label="{label}", '
            f'color="{color}", '
            f'fontcolor="{color}", '
            f'style="{style}", '
            f'penwidth={width}];'
        )

    lines.append("}")

    return "\n".join(lines)


# =========================================================
# MAIN
# =========================================================

def main():

    RESULTS.mkdir(parents=True, exist_ok=True)

    alphabet = [

        "CONNECT",
        "DISCONNECT",
        "QUERY_STATE",
        "READ",
        "WRITE",
        "BROWSE",
        "BROWSE_DEEP",
        "GET_STATUS",
        "CREATE_SUB",
        "DELETE_SUB",
        "CREATE_MON",
        "DELETE_MON"
    ]

    print("=" * 65)
    print("OPC UA STATE MACHINE LEARNING")
    print("=" * 65)

    print("Server:", SERVER_URL)
    print("Security: Basic256Sha256")
    print("Message Security Mode: SignAndEncrypt")
    print("Authentication: Username/password")
    print("Username:", USERNAME)
    print("Alphabet:", len(alphabet), "symbols")
    print("Results:", RESULTS)

    print("=" * 65)

    sul = AutoReconnectSUL()

    try:

        sul._check_certificates()

        eq_oracle = RandomWalkEqOracle(

            alphabet=alphabet,

            sul=sul,

            num_steps=200,

            reset_after_cex=True,

            reset_prob=0.1
        )

        print("\nRunning AALpy L* algorithm...")
        print("Please keep the Python OPC UA server running.")
        print("-" * 65)

        model = run_Lstar(

            alphabet=alphabet,

            sul=sul,

            eq_oracle=eq_oracle,

            automaton_type="mealy",

            cache_and_non_det_check=True,

            print_level=2
        )

        rows = extract_model(model, alphabet)

        labels = label_states(model)

        print("\n" + "=" * 65)
        print("LEARNING RESULT")
        print("=" * 65)

        print("States learned:", len(model.states))

        for state in model.states:

            output = getattr(state, "output_fun", {})

            is_initial = (
                state == model.initial_state
            )

            sid = state.state_id

            query_state = output.get(
                "QUERY_STATE",
                "?"
            )

            tag = " (START)" if is_initial else ""

            print(
                f"\nState {sid}{tag} [{query_state}]:"
            )

            for symbol in alphabet:

                result = output.get(symbol, "?")

                transition = state.transitions.get(
                    symbol
                )

                target = (
                    getattr(transition, "state_id", "?")
                    if transition else "?"
                )

                movement = (
                    "(self)"
                    if target == sid
                    else f"-> {target}"
                )

                print(
                    f"  {symbol:15} / "
                    f"{result:22} {movement}"
                )

        # Save DOT
        dot = build_dot(
            model,
            alphabet,
            rows,
            labels
        )

        dot_path = RESULTS / (
            "python_server_state_machine.dot"
        )

        dot_path.write_text(
            dot,
            encoding="utf-8"
        )

        # Save statistics
        stats_path = RESULTS / (
            "python_server_learning_stats.txt"
        )

        with stats_path.open(
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "OPC UA Python Validation State Machine\n"
            )

            file.write("=" * 45 + "\n\n")

            file.write(
                f"Server: {SERVER_URL}\n"
            )

            file.write(
                "Security: Basic256Sha256\n"
            )

            file.write(
                "Message Security Mode: SignAndEncrypt\n"
            )

            file.write(
                "Authentication: Username/password\n"
            )

            file.write(
                "Algorithm: L* (AALpy)\n"
            )

            file.write(
                "Automaton: Mealy machine\n"
            )

            file.write(
                f"Alphabet size: {len(alphabet)}\n"
            )

            file.write(
                f"Learned states: {len(model.states)}\n\n"
            )

            file.write("Transitions:\n")

            for source, symbol, output, target in rows:

                file.write(
                    f"{source} --{symbol}/{output}--> "
                    f"{target}\n"
                )

        print("\nDOT saved:", dot_path)
        print("Statistics saved:", stats_path)

        print("\nOpen the DOT file using:")
        print(
            "https://dreampuf.github.io/GraphvizOnline/"
        )

    finally:

        try:
            sul.loop.run_until_complete(
                sul._full_reset()
            )
        except Exception:
            pass

        sul.loop.close()

    print("\nLearning finished.")


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print("\nLearning interrupted.")

    except Exception as exc:
        print("\nLEARNING FAILED:")
        print(type(exc).__name__, exc)
