"""
ShieldAI Phase 1 — Real-Time Intrusion Detection
=================================================
NEW in Phase 1:
  • Live packet capture (Scapy/PyShark)
  • WebSocket streaming (Flask-SocketIO)
  • Sliding window aggregation (5-second windows)
  • Automated alert dispatch (Email + SMS via Twilio)
"""

import os
import time
import threading
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from tensorflow import keras

from utils.flow_extractor import FlowExtractor
from utils.sliding_window import SlidingWindowBuffer
from alerts.dispatcher import AlertDispatcher

# ── App setup ─────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "shieldai-secret-change-in-prod")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Load models ───────────────────────────────────────────────────
print("🔄 Loading ShieldAI models...")
RESULTS_DIR = os.getenv("RESULTS_DIR", "results")

le       = joblib.load(f"{RESULTS_DIR}/label_encoder.pkl")
sc       = joblib.load(f"{RESULTS_DIR}/scaler.pkl")
cnn_lstm = keras.models.load_model(f"{RESULTS_DIR}/best_cnn_lstm.keras")
ae       = keras.models.load_model(f"{RESULTS_DIR}/best_autoencoder.keras")

THRESHOLD = float(np.load(f"{RESULTS_DIR}/ae_threshold.npy")[0]) \
    if os.path.exists(f"{RESULTS_DIR}/ae_threshold.npy") else 9999.0
CLASSES = list(le.classes_)
print(f"✅ Ready — detecting: {CLASSES}")

# ── Alert dispatcher (email + SMS) ────────────────────────────────
dispatcher = AlertDispatcher(
    smtp_host     = os.getenv("SMTP_HOST",     "smtp.gmail.com"),
    smtp_port     = int(os.getenv("SMTP_PORT", "587")),
    smtp_user     = os.getenv("SMTP_USER",     ""),
    smtp_password = os.getenv("SMTP_PASSWORD", ""),
    alert_email   = os.getenv("ALERT_EMAIL",   ""),
    twilio_sid    = os.getenv("TWILIO_SID",    ""),
    twilio_token  = os.getenv("TWILIO_TOKEN",  ""),
    twilio_from   = os.getenv("TWILIO_FROM",   ""),
    alert_phone   = os.getenv("ALERT_PHONE",   ""),
    dashboard_url = os.getenv("DASHBOARD_URL", "http://localhost:5000"),
)

# ── In-memory state ───────────────────────────────────────────────
capture_active = False
capture_thread = None

# ── Attack knowledge base (abbreviated — keep your full KB here) ──
KB = {
    "BENIGN":      {"risk": 0,  "risk_label": "Safe",          "icon": "✅", "color": "#22c55e"},
    "DoS":         {"risk": 92, "risk_label": "Critical",       "icon": "⚡", "color": "#ef4444"},
    "DDoS":        {"risk": 98, "risk_label": "Critical",       "icon": "💥", "color": "#dc2626"},
    "Brute Force": {"risk": 78, "risk_label": "High",           "icon": "🔓", "color": "#f97316"},
    "PortScan":    {"risk": 55, "risk_label": "Medium",         "icon": "🔍", "color": "#eab308"},
    "Bot":         {"risk": 88, "risk_label": "Critical",       "icon": "🤖", "color": "#dc2626"},
    "Infiltration":{"risk": 95, "risk_label": "Critical",       "icon": "🕵️", "color": "#7c3aed"},
    "Patator":     {"risk": 72, "risk_label": "High",           "icon": "🔨", "color": "#f97316"},
    "Heartbleed":  {"risk": 99, "risk_label": "Critical",       "icon": "💔", "color": "#dc2626"},
    "Web Attack":  {"risk": 82, "risk_label": "High",           "icon": "🌐", "color": "#ef4444"},
    "FTP-Patator": {"risk": 68, "risk_label": "High",           "icon": "📁", "color": "#f97316"},
    "SSH-Patator": {"risk": 74, "risk_label": "High",           "icon": "🔑", "color": "#f97316"},
    "UNKNOWN":     {"risk": 85, "risk_label": "Unknown Threat", "icon": "⚠️", "color": "#f97316"},
}


# ── Core prediction logic ─────────────────────────────────────────
def predict_flows(df: pd.DataFrame) -> list:
    """Run the CNN-LSTM + AE ensemble on a feature DataFrame."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    if "Label" in df.columns:
        df.drop(columns=["Label"], inplace=True)
    df.replace([float("inf"), float("-inf")], float("nan"), inplace=True)
    df.fillna(0, inplace=True)

    X = df.values.astype(np.float32)
    exp = sc.n_features_in_
    if X.shape[1] > exp:
        X = X[:, :exp]
    elif X.shape[1] < exp:
        X = np.pad(X, ((0, 0), (0, exp - X.shape[1])))

    X_sc   = sc.transform(X)
    X_3d   = X_sc.reshape(X_sc.shape[0], 1, X_sc.shape[1])
    probs  = cnn_lstm.predict(X_3d, verbose=0)
    ids    = np.argmax(probs, axis=1)
    names  = le.inverse_transform(ids)
    confs  = np.max(probs, axis=1)
    recon  = ae.predict(X_sc, verbose=0)
    errors = np.mean((X_sc - recon) ** 2, axis=1)

    results = []
    for i, (nm, cf, er) in enumerate(zip(names, confs, errors)):
        atk  = "UNKNOWN" if (er > THRESHOLD and float(cf) < 0.50) else nm
        info = KB.get(atk, KB["UNKNOWN"])
        results.append({
            "id":            i + 1,
            "attack":        atk,
            "confidence":    round(float(cf) * 100, 1),
            "risk":          info["risk"],
            "risk_label":    info["risk_label"],
            "icon":          info["icon"],
            "color":         info["color"],
            "anomaly_score": round(float(er), 6),
            "timestamp":     datetime.now().strftime("%H:%M:%S"),
        })
    return results


# ── Live capture loop (runs in background thread) ─────────────────
def _capture_loop(interface: str, window_seconds: int = 5):
    """
    Continuously captures packets, aggregates into windows,
    extracts flow features, runs prediction, and pushes results
    over WebSocket to all connected clients.
    """
    global capture_active
    extractor = FlowExtractor()
    window    = SlidingWindowBuffer(window_seconds=window_seconds)

    socketio.emit("capture_status", {"status": "started", "interface": interface})
    print(f"🎯 Capture started on interface: {interface}")

    try:
        import scapy.all as scapy

        def packet_handler(pkt):
            if not capture_active:
                return
            window.add_packet(pkt)

            # Every time a window closes, extract features and predict
            if window.is_ready():
                packets = window.flush()
                features_df = extractor.extract(packets)
                if features_df is not None and len(features_df) > 0:
                    results = predict_flows(features_df)
                    _emit_and_alert(results, source="live")

        scapy.sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            stop_filter=lambda _: not capture_active,
        )
    except Exception as e:
        socketio.emit("capture_error", {"error": str(e)})
        print(f"❌ Capture error: {e}")
    finally:
        capture_active = False
        socketio.emit("capture_status", {"status": "stopped"})
        print("🛑 Capture stopped.")


def _emit_and_alert(results: list, source: str = "upload"):
    """Push results to WebSocket and fire alerts for high-risk detections."""
    for r in results:
        socketio.emit("detection", {**r, "source": source})

    # Fire alert if any result is HIGH or above (risk >= 70)
    high_risk = [r for r in results if r["risk"] >= 70 and r["attack"] != "BENIGN"]
    if high_risk:
        worst = max(high_risk, key=lambda x: x["risk"])
        dispatcher.dispatch(worst)


# ── REST routes ───────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    """Original CSV upload endpoint — now also streams results via WebSocket."""
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        t0 = time.time()
        df = pd.read_csv(f, low_memory=False)
        results = predict_flows(df)
        elapsed = round(time.time() - t0, 2)

        # Stream each result over WebSocket
        for r in results:
            socketio.emit("detection", {**r, "source": "upload"})

        # Fire alerts for high-risk
        high_risk = [r for r in results if r["risk"] >= 70]
        if high_risk:
            dispatcher.dispatch(max(high_risk, key=lambda x: x["risk"]))

        atk_counts = {}
        for r in results:
            atk_counts[r["attack"]] = atk_counts.get(r["attack"], 0) + 1

        n_attacks  = sum(1 for r in results if r["attack"] != "BENIGN")
        n_critical = sum(1 for r in results if r["risk"] >= 90)

        if n_critical > 0:
            threat_level = "CRITICAL"
        elif n_attacks > len(results) * 0.2:
            threat_level = "HIGH"
        elif n_attacks > 0:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        summary = {
            "total":        len(results),
            "attacks":      n_attacks,
            "normal":       sum(1 for r in results if r["attack"] == "BENIGN"),
            "critical":     n_critical,
            "unknown":      sum(1 for r in results if r["attack"] == "UNKNOWN"),
            "threat_level": threat_level,
            "scan_time":    elapsed,
            "breakdown":    atk_counts,
            "timestamp":    datetime.now().strftime("%d %b %Y, %H:%M:%S"),
        }
        return jsonify({"summary": summary, "results": results[:200]})
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/capture/start", methods=["POST"])
def start_capture():
    """Start live packet capture on a given network interface."""
    global capture_active, capture_thread
    if capture_active:
        return jsonify({"error": "Capture already running"}), 400

    data      = request.get_json() or {}
    interface = data.get("interface", "eth0")
    window_s  = int(data.get("window_seconds", 5))

    capture_active = True
    capture_thread = threading.Thread(
        target=_capture_loop,
        args=(interface, window_s),
        daemon=True,
    )
    capture_thread.start()
    return jsonify({"status": "started", "interface": interface, "window_seconds": window_s})


@app.route("/capture/stop", methods=["POST"])
def stop_capture():
    """Stop the live capture loop."""
    global capture_active
    capture_active = False
    return jsonify({"status": "stopped"})


@app.route("/capture/status")
def capture_status():
    return jsonify({"active": capture_active})


@app.route("/interfaces")
def list_interfaces():
    """Return available network interfaces for the UI dropdown."""
    try:
        import scapy.all as scapy
        ifaces = list(scapy.get_if_list())
    except Exception:
        ifaces = ["eth0", "en0", "lo"]
    return jsonify({"interfaces": ifaces})


# ── WebSocket events ──────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("connected", {"msg": "ShieldAI WebSocket connected", "ts": datetime.now().isoformat()})


@socketio.on("disconnect")
def on_disconnect():
    print("Client disconnected")


# ── Entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("🚀 ShieldAI Phase 1 → http://localhost:5000")
    socketio.run(app, debug=True, port=5000, host="0.0.0.0", allow_unsafe_werkzeug=True)