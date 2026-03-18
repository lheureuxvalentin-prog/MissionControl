from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)
DATA_FILE = '/app/data.json'

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {"briefs": []}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/agents')
def agents():
    return jsonify([
        {"name": "Jarvis", "role": "Chief of Staff", "status": "online", "tags": ["coordination", "arbitration"]},
        {"name": "Scout", "role": "Intelligence Operator", "status": "standby", "tags": ["scanning", "research"]},
        {"name": "Quill", "role": "Writer", "status": "standby", "tags": ["content", "briefs"]}
    ])

@app.route('/api/costs')
def costs():
    return jsonify({"monthly_total": 47.83, "daily_spend": 12.15, "currency": "USD", "month": datetime.now().strftime("%B %Y")})

@app.route('/api/org')
def org():
    return jsonify({"agents": [
        {"name": "Jarvis", "role": "Chief of Staff", "color": "#9b59b6", "note": "Arbitrates when needed"},
        {"name": "Scout", "role": "Intelligence Operator", "color": "#00d4ff"},
        {"name": "Quill", "role": "Writer", "color": "#00ff88"}
    ]})

@app.route('/api/briefs')
def briefs():
    data = load_data()
    return jsonify(data.get('briefs', []))

@app.route('/api/brief/add', methods=['POST'])
def add_brief():
    data = load_data()
    brief = request.json
    brief['date'] = datetime.now().strftime("%Y-%m-%d")
    data['briefs'].insert(0, brief)
    data['briefs'] = data['briefs'][:30]
    save_data(data)
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
