from flask import Flask, jsonify, request
import engine
import db
import threading

app = Flask(__name__)

# --- Control Endpoints ---
@app.route('/start', methods=['GET'])
def start_engine():
    if engine.start_sniffer():
        return jsonify({"status": "success", "message": "Sniffer started."})
    else:
        return jsonify({"status": "error", "message": "Sniffer already running."})

@app.route('/stop', methods=['GET'])
def stop_engine():
    if engine.stop_sniffer():
        return jsonify({"status": "success", "message": "Sniffer stopping."})
    else:
        return jsonify({"status": "error", "message": "Sniffer not running."})

# --- Data/Report Endpoints ---
@app.route('/alerts', methods=['GET'])
def get_all_alerts():
    alerts = db.get_alerts()
    return jsonify(alerts)

@app.route('/stats/graph', methods=['GET'])
def get_graph_stats():
    """Endpoint to get alert stats for the GUI graph."""
    # --- THIS LINE IS CHANGED ---
    stats = db.get_alerts_over_time() 
    return jsonify(stats)
# -----------------------------

@app.route('/stats/counts', methods=['GET'])
def get_live_counts():
    return jsonify({
        "packet_count": engine.packet_count,
        "alert_count": engine.alert_count
    })

@app.route('/status', methods=['GET'])
def get_status():
    return jsonify({"sniffer_active": engine.sniffer_active})

# --- BLOCKING ENDPOINTS ---

@app.route('/blocking/toggle_autoblock', methods=['POST'])
def toggle_autoblock():
    data = request.get_json()
    is_enabled = data.get('enabled', False)
    engine.auto_block_enabled = is_enabled
    print(f"Auto-block set to: {is_enabled}")
    return jsonify({"status": "success", "auto_block_enabled": is_enabled})

@app.route('/blocking/block_ip', methods=['POST'])
def manual_block_ip():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"status": "error", "message": "No IP provided."}), 400
    
    if db.block_ip(ip, "Manual Block via GUI"):
        return jsonify({"status": "success", "message": f"IP {ip} blocked."})
    else:
        return jsonify({"status": "error", "message": "Failed to block IP."})

@app.route('/blocking/list', methods=['GET'])
def get_blocked_list():
    blocked_ips = db.get_blocked_ips()
    return jsonify(blocked_ips)

@app.route('/blocking/unblock_ip', methods=['POST'])
def manual_unblock_ip():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"status": "error", "message": "No IP provided."}), 400
    
    if db.unblock_ip(ip):
        return jsonify({"status": "success", "message": f"IP {ip} unblocked."})
    else:
        return jsonify({"status": "error", "message": "Failed to unblock IP or IP not found."})

# ------------------------------

if __name__ == '__main__':
    flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False), daemon=True)
    flask_thread.start()
    
    print("Flask server is starting at http://127.0.0.1:5000")
    print("Run gui.py in a SEPARATE terminal to see the application.")
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nShutting down backend server...")