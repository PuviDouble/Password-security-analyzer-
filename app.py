from flask import Flask, request, jsonify, send_from_directory
from password_analyzer import PasswordAnalyzer

app = Flask(__name__, static_folder='.', static_url_path='')
analyzer = PasswordAnalyzer()

@app.route('/', methods=['GET'])
def serve_index():
    """Serves the Web Dashboard UI on the root path."""
    return send_from_directory('.', 'index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    """API Health Check Endpoint."""
    return jsonify({"status": "online", "service": "CyberShield Password Security Analyzer API"})

@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    """Analyzes a single password string."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    check_breach = data.get('check_breach', True)

    if not password:
        return jsonify({"error": "Password parameter is required."}), 400

    result = analyzer.analyze(password, check_breach=check_breach)
    return jsonify(result)

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """Analyzes a batch list of passwords."""
    data = request.get_json(silent=True) or {}
    passwords = data.get('passwords', [])
    check_breach = data.get('check_breach', False)

    if not isinstance(passwords, list):
        return jsonify({"error": "Passwords must be a list of strings."}), 400

    results = []
    for pwd in passwords[:100]:
        res = analyzer.analyze(str(pwd), check_breach=check_breach)
        results.append(res)

    return jsonify({"count": len(results), "results": results})

if __name__ == '__main__':
    print("Starting CyberShield Server & Web Dashboard on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
