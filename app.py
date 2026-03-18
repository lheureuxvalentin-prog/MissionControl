import os, json, threading, time, uuid, base64, queue
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
import websocket

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
DEVICE_FILE    = os.getenv('DEVICE_FILE', '/app/device.json')

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
    if os.path.exists(DEVICE_FILE):
        return json.load(open(DEVICE_FILE))

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
def on_open(ws):
    dev = get_device()
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
    print(f"[WS] Auth sent — device {dev['device_id'][:12]}…")
    print(f"[WS] Approve with: openclaw devices approve {dev['request_id']}")
    broadcast({'type': 'gateway_status', 'status': 'authenticating',
               'device_id': dev['device_id'], 'request_id': dev['request_id']})


def on_message(ws, message):
    try:
        ev = json.loads(message)
        t  = ev.get('type', '')
        print(f"[WS] ← {t}")

        with lock:
            if t in ('authenticated', 'paired', 'approved', 'connected', 'ready'):
                state['gateway'] = 'online'
                broadcast({'type': 'gateway_status', 'status': 'online'})

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

            # Log any unknown event for debugging
            else:
                print(f"[WS] Unknown event: {json.dumps(ev)[:200]}")

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


def ws_thread():
    while True:
        try:
            ws = websocket.WebSocketApp(
                OPENCLAW_WS,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )
            ws.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as e:
            print(f"[WS] Connection failed: {e}")
        with lock:
            state['gateway'] = 'reconnecting'
        time.sleep(10)


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
