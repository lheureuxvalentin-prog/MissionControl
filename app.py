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

OPENCLAW_WS    = os.getenv('OPENCLAW_WS_URL', 'ws://127.0.0.1:57627')
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
lock        = threading.Lock()
sse_queues  = []


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


# ── OpenClaw WebSocket handlers ──
_ws_use_device_auth = False   # set by ws_thread before connecting


def on_open(ws):
    if _ws_use_device_auth:
        # Bearer-token path: send device identity JSON
        try:
            dev = get_device()
        except Exception as e:
            print(f"[WS] on_open — get_device() FAILED: {e}")
            import traceback; traceback.print_exc()
            return

        with lock:
            state['gateway']   = 'authenticating'
            state['device_id'] = dev['device_id']

        auth = {
            'type':  'auth',
            'token': OPENCLAW_TOKEN,
            'device': {
                'id':        dev['device_id'],
                'requestId': dev['request_id'],
                'publicKey': dev['public_key'],
                'platform':  'python',
                'role':      'operator',
            }
        }
        ws.send(json.dumps(auth))
        print(f"[WS] Auth sent — device {dev['device_id'][:12]}… requestId={dev['request_id']}")
        broadcast({'type': 'gateway_status', 'status': 'authenticating',
                   'device_id': dev['device_id'], 'request_id': dev['request_id']})
    else:
        # Cookie-session path: already authenticated, just mark as online
        print("[WS] Connected via session cookie — listening for events")
        with lock:
            state['gateway'] = 'online'
        broadcast({'type': 'gateway_status', 'status': 'online'})


def sign_challenge(ws, payload):
    """Sign the nonce with our Ed25519 private key and send the response."""
    nonce = payload.get('nonce', '')
    try:
        dev = get_device()
        if not dev.get('private_key') or not HAS_CRYPTO:
            print("[WS] Cannot sign challenge — no private key")
            return
        priv_bytes = base64.b64decode(dev['private_key'])
        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature   = private_key.sign(nonce.encode('utf-8'))
        sig_b64     = base64.b64encode(signature).decode()
        response = {'type': 'connect.challenge.response', 'nonce': nonce, 'signature': sig_b64}
        ws.send(json.dumps(response))
        print(f"[WS] Challenge signed — nonce {nonce[:8]}…")
    except Exception as e:
        print(f"[WS] Challenge sign failed: {e}")
        import traceback; traceback.print_exc()


def on_message(ws, message):
    try:
        ev = json.loads(message)
        t  = ev.get('type', '')
        ev_name = ev.get('event', '')
        print(f"[WS] ← {t} {ev_name}")

        # ── Challenge-response (device identity) ──
        if t == 'event' and ev_name == 'connect.challenge':
            sign_challenge(ws, ev.get('payload', {}))
            return

        with lock:
            if t in ('authenticated', 'paired', 'approved', 'connected', 'ready') \
               or (t == 'event' and ev_name in ('connect.authenticated', 'connect.approved', 'connect.ready')):
                state['gateway'] = 'online'
                broadcast({'type': 'gateway_status', 'status': 'online'})
                print("[WS] Gateway ONLINE")

            elif t == 'agents':
                agents = ev.get('data', ev.get('agents', []))
                if agents:
                    state['agents'] = agents
                    broadcast({'type': 'agents', 'payload': agents})

            elif t == 'agent_update':
                for a in state['agents']:
                    if a.get('name') == ev.get('name') or a.get('id') == ev.get('id'):
                        a['status'] = ev.get('status', a['status'])
                broadcast({'type': 'agent_update', 'payload': ev})

            elif t == 'costs':
                state['costs'].update(ev.get('data', ev))
                broadcast({'type': 'costs', 'payload': state['costs']})

            elif t == 'error':
                print(f"[WS] OpenClaw error: {ev.get('message', ev)}")

            else:
                print(f"[WS] Unhandled event: {json.dumps(ev)[:300]}")

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


def _http_base():
    return OPENCLAW_WS.replace('ws://', 'http://').replace('wss://', 'https://')


def wait_for_openclaw_ready(timeout=180):
    """Poll HTTP until OpenClaw shows the login page (not the startup screen)."""
    base = _http_base()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = req_lib.get(base, timeout=5, allow_redirects=False)
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
    base = _http_base()
    try:
        r = req_lib.post(
            f"{base.rstrip('/')}/login",
            data={'token': OPENCLAW_TOKEN},
            allow_redirects=False,
            timeout=5,
        )
        sid = r.cookies.get('connect.sid')
        if sid:
            print(f"[WS] Session cookie obtained")
            return f'connect.sid={sid}'
        print(f"[WS] Login returned {r.status_code} but no cookie")
    except Exception as e:
        print(f"[WS] Cookie login failed: {e}")
    return None


def ws_thread():
    while True:
        wait_for_openclaw_ready()

        global _ws_use_device_auth
        cookie = get_session_cookie()
        if cookie:
            headers = {'Cookie': cookie}
            _ws_use_device_auth = False
            print(f"[WS] Connecting with session cookie to {OPENCLAW_WS}")
        else:
            headers = {'Authorization': f'Bearer {OPENCLAW_TOKEN}'}
            _ws_use_device_auth = True
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
                'type':    'init',
                'agents':  state['agents'],
                'costs':   {**state['costs'], 'month': datetime.now().strftime('%B %Y')},
                'org':     state['org'],
                'gateway': state['gateway'],
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
