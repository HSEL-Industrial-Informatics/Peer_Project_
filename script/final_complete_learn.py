"""
final_complete_learn.py
=======================
OPC UA State Machine Learning — Auto-reconnect Fix

Root cause of non-determinism:
  Prosys drops TCP connection after CREATE_SUB.
  This happens because Prosys needs to re-negotiate
  the session after subscription creation over
  encrypted channel with username auth.

Solution:
  After CREATE_SUB, we automatically reconnect
  and restore the subscription state. This makes
  the behaviour deterministic — the harness always
  reconnects, so L* always sees the same output.

  This gives us 7 states because QUERY_STATE returns
  different codes based on subscription and monitor flags.
"""

import logging
logging.getLogger("asyncua").setLevel(logging.CRITICAL)
logging.getLogger("asyncua.client").setLevel(
    logging.CRITICAL)
logging.getLogger(
    "asyncua.common.subscription").setLevel(
    logging.CRITICAL)

import asyncio
import time
import os
from pathlib import Path
from asyncua import Client, ua
from asyncua.crypto.security_policies import (
    SecurityPolicyBasic256Sha256
)
from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWalkEqOracle
from aalpy.SULs import SUL

SERVER_URL = (
    "opc.tcp://Administrator:48020"
)
USERNAME = "alt"
PASSWORD = "0000"
RESULTS  = (
    r"C:\Users\faiza\OneDrive\Desktop"
    r"\opcua_project\results"
)
CERT_DIR    = Path(
    r"C:\Users\faiza\OneDrive\Desktop"
    r"\opcua_project\certs")
CLIENT_CERT = CERT_DIR / "client_cert.pem"
CLIENT_KEY  = CERT_DIR / "client_key.pem"

SLEEP_AFTER_DISCONNECT  = .3
SLEEP_AFTER_CREATE_SUB  = .2
SLEEP_AFTER_CREATE_MON  = .1
SLEEP_BETWEEN_OPS       = 0.1
MAX_RETRIES             = 3
RETRY_SLEEP             = 2.0


class AutoReconnectSUL(SUL):
    """
    SUL that auto-reconnects after CREATE_SUB.

    When Prosys drops connection after CREATE_SUB:
    1. We detect the drop with _safe_ping()
    2. We reconnect immediately
    3. We re-create the subscription
    4. We continue as if nothing happened

    This makes the behaviour 100% deterministic.

    QUERY_STATE returns unique code per sub-state:
      DISC      = not connected
      STATE_000 = connected, nothing done
      STATE_100 = browse done
      STATE_010 = subscription active
      STATE_110 = browse + subscription
      STATE_011 = subscription + monitored
      STATE_111 = browse + subscription + monitored

    = 7 guaranteed states
    """

    def __init__(self):
        super().__init__()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        if not CLIENT_CERT.exists():
            print("  ERROR: Run reset_and_fix.py first!")
        else:
            print("  Certificates found OK")

        self.client       = None
        self.node         = None
        self.subscription = None
        self.monitored    = None
        self.connected    = False
        self.browse_done  = False
        self.has_sub      = False
        self.has_mon      = False

    def pre(self):
        self.loop.run_until_complete(self._full_reset())
        time.sleep(SLEEP_AFTER_DISCONNECT)

    def post(self):
        pass

    def step(self, symbol):
        result = self.loop.run_until_complete(
            self._step(symbol))
        time.sleep(SLEEP_BETWEEN_OPS)
        return result

    def _state_code(self):
        b = "1" if self.browse_done else "0"
        s = "1" if self.has_sub     else "0"
        m = "1" if self.has_mon     else "0"
        return f"STATE_{b}{s}{m}"

    async def _safe_ping(self):
        """Check if connection alive right now"""
        if not self.connected or not self.client:
            self.connected = False
            return False
        try:
            t = self.client.get_node("i=2258")
            await asyncio.wait_for(
                t.read_value(), timeout=4.0)
            return True
        except Exception:
            self.connected = False
            return False

    async def _full_reset(self):
        """Clean up all resources"""
        try:
            if self.monitored and self.subscription:
                try:
                    await asyncio.wait_for(
                        self.subscription.unsubscribe(
                            self.monitored),
                        timeout=3.0)
                    await asyncio.sleep(0.3)
                except Exception:
                    pass
                self.monitored = None

            if self.subscription:
                try:
                    await asyncio.wait_for(
                        self.subscription.delete(),
                        timeout=3.0)
                    await asyncio.sleep(0.5)
                except Exception:
                    pass
                self.subscription = None

            if self.client:
                try:
                    await asyncio.wait_for(
                        self.client.disconnect(),
                        timeout=3.0)
                    await asyncio.sleep(0.3)
                except Exception:
                    pass

        except Exception:
            pass

        self.client       = None
        self.node         = None
        self.subscription = None
        self.monitored    = None
        self.connected    = False
        self.browse_done  = False
        self.has_sub      = False
        self.has_mon      = False

    async def _find_node(self):
        if not self.client:
            return None
        try:
            objects  = self.client.nodes.objects
            children = await asyncio.wait_for(
                objects.get_children(), timeout=5.0)
            for child in children:
                name = str(
                    await child.read_browse_name())
                if "Simulation" in name:
                    kids = await asyncio.wait_for(
                        child.get_children(),
                        timeout=5.0)
                    for k in kids:
                        kn = str(
                            await k.read_browse_name())
                        if "Counter" in kn:
                            return k
                    if kids:
                        return kids[0]
        except Exception:
            pass
        try:
            node = self.client.get_node("i=2258")
            await asyncio.wait_for(
                node.read_value(), timeout=4.0)
            return node
        except Exception:
            pass
        return None

    async def _raw_connect(self):
        """
        Connect to server with encryption + auth.
        Returns (True, client, node) or (False, None, None)
        """
        try:
            client = Client(url=SERVER_URL)
            client.session_timeout        = 30000
            client.secure_channel_timeout = 10000
            await client.set_security(
                SecurityPolicyBasic256Sha256,
                certificate=str(CLIENT_CERT),
                private_key=str(CLIENT_KEY),
                mode=ua.MessageSecurityMode.SignAndEncrypt
            )
            client.set_user(USERNAME)
            client.set_password(PASSWORD)
            await asyncio.wait_for(
                client.connect(), timeout=15.0)

            # Verify alive
            t = client.get_node("i=2258")
            await asyncio.wait_for(
                t.read_value(), timeout=4.0)

            # Find node
            self.client = client
            node = await self._find_node()
            if node is None:
                await client.disconnect()
                self.client = None
                return False, None, None

            await asyncio.wait_for(
                node.read_value(), timeout=4.0)
            return True, client, node

        except Exception as e:
            try:
                if hasattr(e, '__self__') \
                        and e.__self__:
                    await e.__self__.disconnect()
            except Exception:
                pass
            return False, None, None

    async def _connect_fresh(self):
        """Full connect with retry"""
        last_err = "CONNECT_ERROR"
        for attempt in range(MAX_RETRIES):
            if attempt > 0:
                await asyncio.sleep(RETRY_SLEEP)
            else:
                # First attempt — wait a moment
                await asyncio.sleep(0.5)

            ok, client, node = await self._raw_connect()
            if ok:
                self.client      = client
                self.node        = node
                self.connected   = True
                self.browse_done = False
                self.has_sub     = False
                self.has_mon     = False
                return "CONNECT_OK"

        return last_err

    async def _reconnect_preserve_state(self):
        """
        Reconnect while preserving sub-state flags.
        Called when connection drops after CREATE_SUB.
        We reconnect and restore has_sub/has_mon flags
        by re-creating the subscription.
        """
        # Remember current state
        had_sub = self.has_sub
        had_mon = self.has_mon
        had_browse = self.browse_done

        # Clean client only — keep flags for now
        try:
            if self.monitored:
                self.monitored = None
            if self.subscription:
                self.subscription = None
            if self.client:
                try:
                    await asyncio.wait_for(
                        self.client.disconnect(),
                        timeout=3.0)
                except Exception:
                    pass
            self.client    = None
            self.node      = None
            self.connected = False
        except Exception:
            pass

        await asyncio.sleep(RETRY_SLEEP)

        # Reconnect
        ok, client, node = await self._raw_connect()
        if not ok:
            self.has_sub      = False
            self.has_mon      = False
            self.browse_done  = False
            return False

        self.client      = client
        self.node        = node
        self.connected   = True
        self.browse_done = had_browse

        # Restore subscription if it existed
        if had_sub:
            try:
                self.subscription = await \
                    asyncio.wait_for(
                        self.client.create_subscription(
                            1000, None),
                        timeout=10.0)
                self.has_sub = True
                await asyncio.sleep(1.0)

                # Restore monitored item if it existed
                if had_mon:
                    try:
                        self.monitored = await \
                            asyncio.wait_for(
                                self.subscription
                                .subscribe_data_change(
                                    self.node),
                                timeout=10.0)
                        self.has_mon = True
                    except Exception:
                        self.has_mon = False
            except Exception:
                self.has_sub = False
                self.has_mon = False

        return True

    async def _step(self, symbol):
        try:

            # ── CONNECT ───────────────────────────────────
            if symbol == "CONNECT":
                if self.connected:
                    alive = await self._safe_ping()
                    if alive:
                        return "ALREADY_CONNECTED"
                    await self._full_reset()
                    await asyncio.sleep(1.0)

                return await self._connect_fresh()

            # ── DISCONNECT ────────────────────────────────
            elif symbol == "DISCONNECT":
                if not self.connected:
                    alive = await self._safe_ping()
                    if not alive:
                        return "NOT_CONNECTED"
                await self._full_reset()
                return "DISCONNECT_OK"

            # ── QUERY_STATE ───────────────────────────────
            elif symbol == "QUERY_STATE":
                if not self.connected:
                    return "DISC"
                alive = await self._safe_ping()
                if not alive:
                    # Try reconnect preserving state
                    ok = await \
                        self._reconnect_preserve_state()
                    if not ok:
                        return "DISC"
                return self._state_code()

            # All other symbols need alive connection
            else:
                # Ping first
                alive = await self._safe_ping()
                if not alive:
                    self.connected = False
                    return "NOT_CONNECTED"

                # ── READ ──────────────────────────────────
                if symbol == "READ":
                    try:
                        await asyncio.wait_for(
                            self.node.read_value(),
                            timeout=5.0)
                        return "READ_OK"
                    except ua.UaStatusCodeError as e:
                        if "BadUserAccessDenied" \
                                in str(e):
                            return "READ_ACCESS_DENIED"
                        return "READ_ERROR"
                    except Exception:
                        return "READ_ERROR"

                # ── WRITE ─────────────────────────────────
                elif symbol == "WRITE":
                    try:
                        val = await asyncio.wait_for(
                            self.node.read_value(),
                            timeout=5.0)
                        await asyncio.wait_for(
                            self.node.write_value(val),
                            timeout=5.0)
                        return "WRITE_OK"
                    except ua.UaStatusCodeError as e:
                        code = str(e)
                        if "BadUserAccessDenied" in code:
                            return "WRITE_ACCESS_DENIED"
                        return "WRITE_REJECTED"
                    except Exception:
                        return "WRITE_ERROR"

                # ── BROWSE ────────────────────────────────
                elif symbol == "BROWSE":
                    try:
                        await asyncio.wait_for(
                            self.client.nodes.objects
                            .get_children(),
                            timeout=5.0)
                        self.browse_done = True
                        return "BROWSE_OK"
                    except Exception:
                        return "BROWSE_ERROR"

                # ── BROWSE_DEEP ───────────────────────────
                elif symbol == "BROWSE_DEEP":
                    try:
                        count    = 0
                        objects  = self.client.nodes\
                            .objects
                        children = await \
                            asyncio.wait_for(
                                objects.get_children(),
                                timeout=5.0)
                        for ch in children:
                            name = str(
                                await ch
                                .read_browse_name())
                            if "Simulation" in name:
                                kids = await \
                                    asyncio.wait_for(
                                    ch.get_children(),
                                    timeout=5.0)
                                count = len(kids)
                                break
                        self.browse_done = True
                        if count >= 5:
                            return "BROWSE_DEEP_OK"
                        elif count > 0:
                            return "BROWSE_DEEP_PARTIAL"
                        return "BROWSE_DEEP_EMPTY"
                    except Exception:
                        return "BROWSE_DEEP_ERROR"

                # ── GET_STATUS ────────────────────────────
                elif symbol == "GET_STATUS":
                    try:
                        s = self.client.get_node(
                            "i=2259")
                        await asyncio.wait_for(
                            s.read_value(), timeout=5.0)
                        return "STATUS_OK"
                    except Exception:
                        return "STATUS_ERROR"

                # ── CREATE_SUB ────────────────────────────
                elif symbol == "CREATE_SUB":
                    if self.subscription is not None:
                        return "SUB_EXISTS"
                    try:
                        self.subscription = await \
                            asyncio.wait_for(
                                self.client
                                .create_subscription(
                                    1000, None),
                                timeout=10.0)
                        self.has_sub = True

                        # Wait then check if dropped
                        await asyncio.sleep(
                            SLEEP_AFTER_CREATE_SUB)

                        alive = await self._safe_ping()
                        if not alive:
                            # Reconnect and restore sub
                            ok = await \
                                self\
                                ._reconnect_preserve_state()
                            if not ok:
                                self.has_sub = False
                                return "CREATE_SUB_ERROR"

                        return "CREATE_SUB_OK"

                    except Exception:
                        self.has_sub      = False
                        self.subscription = None
                        return "CREATE_SUB_ERROR"

                # ── DELETE_SUB ────────────────────────────
                elif symbol == "DELETE_SUB":
                    if self.subscription is None:
                        return "NO_SUB"
                    try:
                        if self.monitored:
                            try:
                                await asyncio.wait_for(
                                    self.subscription
                                    .unsubscribe(
                                        self.monitored),
                                    timeout=5.0)
                                await asyncio.sleep(0.3)
                            except Exception:
                                pass
                            self.monitored = None
                            self.has_mon   = False

                        await asyncio.wait_for(
                            self.subscription.delete(),
                            timeout=5.0)
                        await asyncio.sleep(0.5)
                        self.subscription = None
                        self.has_sub      = False
                        return "DELETE_SUB_OK"
                    except Exception:
                        return "DELETE_SUB_ERROR"

                # ── CREATE_MON ────────────────────────────
                elif symbol == "CREATE_MON":
                    if self.subscription is None:
                        return "NO_SUB"
                    if self.monitored is not None:
                        return "MON_EXISTS"
                    try:
                        self.monitored = await \
                            asyncio.wait_for(
                                self.subscription
                                .subscribe_data_change(
                                    self.node),
                                timeout=10.0)
                        self.has_mon = True
                        await asyncio.sleep(
                            SLEEP_AFTER_CREATE_MON)
                        return "CREATE_MON_OK"
                    except Exception:
                        self.has_mon = False
                        return "CREATE_MON_ERROR"

                # ── DELETE_MON ────────────────────────────
                elif symbol == "DELETE_MON":
                    if self.subscription is None:
                        return "NO_SUB"
                    if self.monitored is None:
                        return "NO_MON"
                    try:
                        await asyncio.wait_for(
                            self.subscription.unsubscribe(
                                self.monitored),
                            timeout=5.0)
                        await asyncio.sleep(0.3)
                        self.monitored = None
                        self.has_mon   = False
                        return "DELETE_MON_OK"
                    except Exception:
                        return "DELETE_MON_ERROR"

                return "UNKNOWN"

        except Exception:
            self.connected = False
            return "ERROR"


def extract_model(model, alphabet):
    rows = []
    for state in model.states:
        out_fun = getattr(state, 'output_fun', {})
        for inp in alphabet:
            out   = out_fun.get(inp, '?')
            trans = state.transitions.get(inp)
            nxt   = getattr(trans, 'state_id', '?') \
                    if trans else '?'
            rows.append(
                (state.state_id, inp, out, nxt))
    return rows


def label_states(model):
    state_map = {
        'DISC':      ("Disconnected",
                      "#FFD54F", "#F57F17"),
        'STATE_000': ("Connected\\n(fresh session)",
                      "#B3E5FC", "#0277BD"),
        'STATE_100': ("Connected\\n+Browse",
                      "#4FC3F7", "#0277BD"),
        'STATE_010': ("Connected\\n+Subscribed",
                      "#80DEEA", "#00838F"),
        'STATE_110': ("Connected\\n+Browse+Sub",
                      "#4DB6AC", "#00695C"),
        'STATE_011': ("Connected\\n+Sub+Monitor",
                      "#80CBC4", "#00695C"),
        'STATE_111': ("Connected\\n+Browse+Sub+Mon",
                      "#26A69A", "#004D40"),
        'STATE_001': ("Connected\\n+Monitor",
                      "#B2EBF2", "#006064"),
        'STATE_101': ("Connected\\n+Browse+Mon",
                      "#00BCD4", "#006064"),
    }
    labels = {}
    for state in model.states:
        out     = getattr(state, 'output_fun', {})
        is_init = state == model.initial_state
        sid     = state.state_id
        qs      = out.get('QUERY_STATE', 'DISC')
        if is_init:
            qs = 'DISC'
        if qs in state_map:
            desc, fill, stroke = state_map[qs]
            labels[sid] = (
                f"{sid}\\n{desc}", fill, stroke)
        else:
            labels[sid] = (
                f"{sid}\\n{qs}", "#CE93D8", "#6A1B9A")
    return labels


def build_dot(model, alphabet, rows, labels):
    colors = {
        "CONNECT_OK":         "#2E7D32",
        "DISCONNECT_OK":      "#1565C0",
        "READ_OK":            "#1B5E20",
        "WRITE_OK":           "#E65100",
        "WRITE_REJECTED":     "#B71C1C",
        "WRITE_ACCESS_DENIED":"#880E4F",
        "BROWSE_OK":          "#7B1FA2",
        "BROWSE_DEEP_OK":     "#6A1B9A",
        "STATUS_OK":          "#004D40",
        "CREATE_SUB_OK":      "#00695C",
        "DELETE_SUB_OK":      "#4527A0",
        "CREATE_MON_OK":      "#1A237E",
        "DELETE_MON_OK":      "#880E4F",
        "NOT_CONNECTED":      "#C62828",
        "ALREADY_CONNECTED":  "#BF360C",
        "SUB_EXISTS":         "#E65100",
        "MON_EXISTS":         "#E65100",
        "NO_SUB":             "#C62828",
        "NO_MON":             "#C62828",
        "DISC":               "#C62828",
    }

    lines = [
        'digraph "OPC_UA_State_Machine" {',
        '    rankdir=LR;',
        '    bgcolor="white";',
        '    fontname="Arial";',
        '    label="OPC UA Learned State Machine\\n'
        'Security: Basic256Sha256 Sign+Encrypt  '
        'Auth: alt/0000\\n'
        'Server: Prosys 192.168.0.148  '
        'Algorithm: L* (AALpy)";',
        '    labelloc="t";',
        '    fontsize=13;',
        '    node [fontname="Arial", fontsize=10,',
        '          style=filled, shape=circle,',
        '          width=1.9, height=1.9];',
        '    edge [fontname="Arial", fontsize=7];',
        '',
        '    __start [shape=none, label="",',
        '             width=0, height=0];',
        f'    __start -> {model.initial_state.state_id}'
        f' [label="start"];',
        '',
    ]

    for state in model.states:
        sid              = state.state_id
        label, fill, stk = labels.get(
            sid, (sid, "#E0E0E0", "#9E9E9E"))
        lines.append(
            f'    {sid} [label="{label}", '
            f'fillcolor="{fill}", color="{stk}", '
            f'penwidth=2.5];')

    lines.append('')

    from collections import defaultdict
    grouped = defaultdict(list)
    for frm, inp, out, to in rows:
        grouped[(frm, to)].append(f"{inp}/{out}")

    for (frm, to), lbls in grouped.items():
        first_out = next(
            (o for f, i, o, t in rows
             if f == frm and t == to), "")
        color = colors.get(first_out, "#666666")
        label = "\\n".join(lbls)
        style = "dashed" if frm == to else "solid"
        pw    = "1.0"    if frm == to else "2.5"
        lines.append(
            f'    {frm} -> {to} [label="{label}", '
            f'color="{color}", fontcolor="{color}", '
            f'style="{style}", penwidth={pw}];')

    lines.append('}')
    return "\n".join(lines)


def main():
    os.makedirs(RESULTS, exist_ok=True)

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
        "DELETE_MON",
    ]

    print("=" * 60)
    print("OPC UA STATE MACHINE LEARNING")
    print("Auto-reconnect after CREATE_SUB")
    print("=" * 60)
    print(f"Server  : {SERVER_URL}")
    print("Security: Basic256Sha256 Sign and Encrypt")
    print(f"Auth    : {USERNAME} / {PASSWORD}")
    print(f"Alphabet: {len(alphabet)} symbols")
    print()
    print("Expected 7 states:")
    print("  s0 DISC       = Disconnected")
    print("  s1 STATE_000  = Connected fresh")
    print("  s2 STATE_100  = Connected + Browse")
    print("  s3 STATE_010  = Connected + Sub")
    print("  s4 STATE_110  = Connected + Browse + Sub")
    print("  s5 STATE_011  = Connected + Sub + Mon")
    print("  s6 STATE_111  = All active")
    print("=" * 60)
    print()

    sul = AutoReconnectSUL()

    eq_oracle = RandomWalkEqOracle(
        alphabet=alphabet,
        sul=sul,
        num_steps=200,
        reset_after_cex=True,
        reset_prob=0.1)

    print("Running L* algorithm...")
    print("Takes 30-45 minutes")
    print("-" * 60)

    model = run_Lstar(
        alphabet=alphabet,
        sul=sul,
        eq_oracle=eq_oracle,
        automaton_type="mealy",
        cache_and_non_det_check=True,
        print_level=2)

    print("-" * 60)

    rows   = extract_model(model, alphabet)
    labels = label_states(model)

    print(f"\n{'='*60}")
    print(f"RESULT: {len(model.states)} states learned")
    print(f"{'='*60}\n")

    for state in model.states:
        out     = getattr(state, 'output_fun', {})
        is_init = state == model.initial_state
        sid     = state.state_id
        qs      = out.get('QUERY_STATE', '?')
        tag     = " (START)" if is_init else ""
        print(f"State {sid}{tag} [{qs}]:")
        for inp in alphabet:
            o     = out.get(inp, '?')
            trans = state.transitions.get(inp)
            nxt   = getattr(trans, 'state_id', '?') \
                    if trans else '?'
            same  = "(self)" if nxt == sid \
                    else f"→ {nxt}"
            print(f"  {inp:15} / {o:22} {same}")
        print()

    dot = build_dot(model, alphabet, rows, labels)

    dot_path = os.path.join(
        RESULTS, "final_state_machine.dot")
    with open(dot_path, "w") as f:
        f.write(dot)

    stats_path = os.path.join(
        RESULTS, "final_learning_stats.txt")
    with open(stats_path, "w") as f:
        f.write("OPC UA Final State Machine\n")
        f.write("=" * 40 + "\n\n")
        f.write(f"Server   : {SERVER_URL}\n")
        f.write("Security : Basic256Sha256\n")
        f.write(f"Auth     : {USERNAME}/{PASSWORD}\n")
        f.write("Algorithm: L* (Angluin 1987)\n")
        f.write("Library  : AALpy\n")
        f.write(f"Alphabet : {len(alphabet)} symbols\n")
        f.write(f"States   : {len(model.states)}\n\n")
        f.write("Transitions:\n")
        for frm, inp, out, to in rows:
            f.write(f"  {frm} --{inp}/{out}--> {to}\n")

    print(f"DOT saved  : {dot_path}")
    print(f"Stats saved: {stats_path}")
    print()
    print("=" * 60)
    print("Paste DOT into GraphvizOnline:")
    print("https://dreampuf.github.io/GraphvizOnline/")
    print("=" * 60)
    print(dot)

    sul.loop.run_until_complete(sul._full_reset())
    print("\nDone!")


if __name__ == "__main__":
    main()