import os, json, threading, time, uuid, base64, queue
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
import websocket
import requests as req_lib

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption
    )
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[WARN] cryptography not installed — device identity disabled")

app = Flask(__name__)
CORS(app)

# Proxy at 57627 is the only accessible WS endpoint (18789 is container-internal only)
OPENCLAW_WS    = os.getenv('OPENCLAW_WS_URL',   'ws://127.0.0.1:57627')
OPENCLAW_HTTP  = os.getenv('OPENCLAW_HTTP_URL', 'http://127.0.0.1:57627')
OPENCLAW_TOKEN = os.getenv('OPENCLAW_TOKEN', '')
DATA_FILE      = os.getenv('DATA_FILE', '/app/data.json')
DEVICE_FILE    = os.getenv('DEVICE_FILE', '/app/state/device.json')

# ── Fallback state (shown before OpenClaw connects) ──
state = {
    'agents': [
        {'name': 'Jarvis', 'role': 'Chief of Staff',        'status': 'standby', 'tags': ['coordination', 'arbitration']},
        {'name': 'Scout',  'role': 'Intelligence Operator', 'status': 'standby', 'tags': ['scanning', 'research']},
        {'name': 'Quill',  'role': 'Writer',                'status': 'standby', 'tags': ['content', 'briefs']},
    ],
    'costs': {'monthly_total': 0.0, 'daily_spend': 0.0, 'currency': 'USD', 'month': ''},
    'org': {'agents': [
        {'name': 'Jarvis', 'role': 'Chief of Staff',        'color': '#a855f7', 'note': 'Arbitrates when needed'},
        {'name': 'Scout',  'role': 'Intelligence Operator', 'color': '#00e5ff'},
        {'name': 'Quill',  'role': 'Writer',                'color': '#00ff88'},
    ]},
    'gateway':   'connecting',
    'device_id': None,
}
lock       = threading.Lock()
sse_queues = []


# ── Device identity (Ed25519) ──
def get_device():
    if os.path.exists(DEVICE_FILE) and os.path.isfile(DEVICE_FILE):
        try:
            content = open(DEVICE_FILE).read().strip()
            if content:
                return json.loads(content)
        except Exception as e:
            print(f"[DEVICE] Failed to read {DEVICE_FILE}: {e}")

    if HAS_CRYPTO:
        key  = Ed25519PrivateKey.generate()
        priv = base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
        pub  = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    else:
        priv = pub = ''

    device = {
        'device_id':  uuid.uuid4().hex,
        'request_id': str(uuid.uuid4()),
        'public_key': pub,
        'private_key': priv,
    }
    json.dump(device, open(DEVICE_FILE, 'w'), indent=2)
    print(f"[DEVICE] New device created: {device['device_id']}")
    return device


# ── SSE broadcast ──
def broadcast(data):
    msg = f"data: {json.dumps(data)}\n\n"
    for q in sse_queues[:]:
        try:
            q.put_nowait(msg)
        except queue.Full:
            pass


# ── OpenClaw WS protocol (gateway JSON-RPC format) ──

def sign_and_connect(ws, nonce):
    """Sign the challenge nonce and send the connect request frame."""
    if not HAS_CRYPTO:
        print("[WS] Cannot sign — cryptography not installed")
        return
    try:
        dev = get_device()
        signed_at_ms = int(time.time() * 1000)
        client_id   = 'openclaw-control-ui'
        client_mode = 'ui'
        role        = 'operator'
        scopes      = ['operator.admin', 'operator.approvals', 'operator.pairing']

        # v2 payload — same format as the browser control-ui
        payload_str = '|'.join([
            'v2', dev['device_id'], client_id, client_mode, role,
            ','.join(scopes), str(signed_at_ms), OPENCLAW_TOKEN, nonce,
        ])

        priv_bytes  = base64.b64decode(dev['private_key'])
        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature   = private_key.sign(payload_str.encode('utf-8'))
        sig_b64url  = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        # Public key in URL-safe base64 without padding (matches paired.json)
        pub_bytes   = base64.b64decode(dev['public_key'])
        pub_b64url  = base64.urlsafe_b64encode(pub_bytes).rstrip(b'=').decode()

        connect_req = {
            'type':   'req',
            'id':     str(uuid.uuid4()),
            'method': 'connect',
            'params': {
                'minProtocol': 3,
                'maxProtocol': 3,
                'client': {
                    'id':       client_id,
                    'version':  '1.0.0',
                    'platform': 'python',
                    'mode':     client_mode,
                },
                'role':   role,
                'scopes': scopes,
                'device': {
                    'id':        dev['device_id'],
                    'publicKey': pub_b64url,
                    'signature': sig_b64url,
                    'signedAt':  signed_at_ms,
                    'nonce':     nonce,
                },
                'auth': {'token': OPENCLAW_TOKEN},
            }
        }
        ws.send(json.dumps(connect_req))
        with lock:
            state['device_id'] = dev['device_id']
        print(f"[WS] Connect sent — device {dev['device_id'][:12]}…  nonce={nonce[:8]}…")
    except Exception as e:
        print(f"[WS] sign_and_connect failed: {e}")
        import traceback; traceback.print_exc()


def on_open(ws):
    print("[WS] Connected — waiting for connect.challenge")
    with lock:
        state['gateway'] = 'authenticating'
    broadcast({'type': 'gateway_status', 'status': 'authenticating'})


def on_message(ws, message):
    try:
        ev      = json.loads(message)
        ev_type = ev.get('type', '')

        # ── Challenge: sign and send connect frame ──
        if ev_type == 'event' and ev.get('event') == 'connect.challenge':
            nonce = (ev.get('payload') or {}).get('nonce', '')
            print(f"[WS] Challenge received — nonce {nonce[:8]}…")
            sign_and_connect(ws, nonce)
            return

        # ── Connect response (hello-ok) ──
        if ev_type == 'res':
            ok      = ev.get('ok', False)
            payload = ev.get('payload') or {}
            print(f"[WS] ← res ok={ok}")
            if ok:
                snapshot = payload.get('snapshot') or {}
                health   = snapshot.get('health') or {}
                agents   = health.get('agents', [])
                with lock:
                    state['gateway'] = 'online'
                    if agents:
                        state['agents'] = agents
                broadcast({'type': 'gateway_status', 'status': 'online'})
                if agents:
                    broadcast({'type': 'agents', 'payload': agents})
                print("[WS] Gateway ONLINE")
            else:
                err = ev.get('error') or {}
                print(f"[WS] Connect rejected: {err}")
                with lock:
                    state['gateway'] = 'error'
                broadcast({'type': 'gateway_status', 'status': 'error'})
            return

        # ── Ongoing gateway events ──
        if ev_type == 'event':
            ev_name = ev.get('event', '')
            payload = ev.get('payload') or {}
            print(f"[WS] ← event {ev_name}")

            with lock:
                if ev_name == 'health':
                    agents = payload.get('agents', [])
                    if agents:
                        state['agents'] = agents
                    broadcast({'type': 'agents', 'payload': state['agents']})

                elif ev_name == 'agent':
                    agent_id = payload.get('id') or payload.get('name')
                    for a in state['agents']:
                        if a.get('id') == agent_id or a.get('name') == agent_id:
                            if 'status' in payload:
                                a['status'] = payload['status']
                    broadcast({'type': 'agent_update', 'payload': payload})

                elif ev_name in ('heartbeat', 'tick', 'presence', 'system-presence'):
                    pass  # ignore

                else:
                    print(f"[WS] Unhandled event: {json.dumps(ev)[:300]}")
            return

        print(f"[WS] Unknown frame: {json.dumps(ev)[:200]}")

    except Exception as e:
        print(f"[WS] Parse error: {e} — raw: {message[:100]}")


def on_error(ws, error):
    print(f"[WS] Error: {error}")
    with lock:
        state['gateway'] = 'error'
    broadcast({'type': 'gateway_status', 'status': 'error'})


def on_close(ws, code, msg):
    print(f"[WS] Closed: {code} {msg}")
    with lock:
        state['gateway'] = 'reconnecting'
    broadcast({'type': 'gateway_status', 'status': 'reconnecting'})


# ── HTTP helpers ──
def wait_for_openclaw_ready(timeout=180):
    """Poll HTTP until OpenClaw shows the login page (not the startup screen)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = req_lib.get(OPENCLAW_HTTP, timeout=5, allow_redirects=False)
            if 'Welcome to OpenClaw' in r.text or r.status_code in (302, 301):
                print("[WS] OpenClaw ready")
                return True
            if 'Starting OpenClaw' in r.text:
                print("[WS] OpenClaw still starting…")
            else:
                print(f"[WS] Unexpected response ({r.status_code}), waiting…")
        except Exception as e:
            print(f"[WS] Waiting for OpenClaw: {e}")
        time.sleep(8)
    print("[WS] OpenClaw did not become ready in time, attempting anyway")
    return False


def get_session_cookie():
    """POST /login with token and return the session Cookie header value."""
    try:
        r = req_lib.post(
            f"{OPENCLAW_HTTP.rstrip('/')}/login",
            data={'token': OPENCLAW_TOKEN},
            allow_redirects=False,
            timeout=5,
        )
        sid = r.cookies.get('connect.sid')
        if sid:
            print("[WS] Session cookie obtained")
            return f'connect.sid={sid}'
        print(f"[WS] Login returned {r.status_code} but no cookie")
    except Exception as e:
        print(f"[WS] Cookie login failed: {e}")
    return None


def ws_thread():
    while True:
        wait_for_openclaw_ready()

        cookie = get_session_cookie()
        if cookie:
            headers = {'Cookie': cookie}
            print(f"[WS] Connecting with session cookie to {OPENCLAW_WS}")
        else:
            headers = {'Authorization': f'Bearer {OPENCLAW_TOKEN}'}
            print(f"[WS] Connecting with Bearer token to {OPENCLAW_WS}")

        try:
            ws = websocket.WebSocketApp(
                OPENCLAW_WS,
                header=headers,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )
            ret = ws.run_forever(ping_interval=30, ping_timeout=10)
            print(f"[WS] run_forever returned: {ret}")
        except Exception as e:
            print(f"[WS] Connection failed: {e}")
            import traceback; traceback.print_exc()
        with lock:
            state['gateway'] = 'reconnecting'
        print("[WS] Reconnecting in 30s…")
        time.sleep(30)


# ── Data helpers ──
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    return {'briefs': []}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)


# ── Routes ──
@app.route('/')
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'index.html')

@app.route('/api/agents')
def agents():
    with lock:
        return jsonify(state['agents'])

@app.route('/api/costs')
def costs():
    with lock:
        c = dict(state['costs'])
    c['month'] = datetime.now().strftime('%B %Y')
    return jsonify(c)

@app.route('/api/org')
def org():
    with lock:
        return jsonify(state['org'])

@app.route('/api/gateway')
def gateway():
    with lock:
        return jsonify({'status': state['gateway'], 'device_id': state['device_id']})

@app.route('/api/briefs')
def briefs():
    return jsonify(load_data().get('briefs', []))

@app.route('/api/brief/add', methods=['POST'])
def add_brief():
    data  = load_data()
    brief = request.json
    brief['date'] = datetime.now().strftime('%Y-%m-%d')
    data['briefs'].insert(0, brief)
    data['briefs'] = data['briefs'][:30]
    save_data(data)
    broadcast({'type': 'new_brief', 'payload': brief})
    return jsonify({'status': 'ok'})

@app.route('/api/stream')
def stream():
    q = queue.Queue(maxsize=50)
    sse_queues.append(q)

    def generate():
        with lock:
            initial = {
                'type':      'init',
                'agents':    state['agents'],
                'costs':     {**state['costs'], 'month': datetime.now().strftime('%B %Y')},
                'org':       state['org'],
                'gateway':   state['gateway'],
                'device_id': state['device_id'],
            }
        yield f"data: {json.dumps(initial)}\n\n"

        try:
            while True:
                try:
                    yield q.get(timeout=25)
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            if q in sse_queues:
                sse_queues.remove(q)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


if __name__ == '__main__':
    if OPENCLAW_TOKEN:
        threading.Thread(target=ws_thread, daemon=True).start()
        print(f"[WS] Connecting to {OPENCLAW_WS}…")
    else:
        print("[WS] No OPENCLAW_TOKEN — running in static mode")
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, threaded=True)
