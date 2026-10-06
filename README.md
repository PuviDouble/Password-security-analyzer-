# 🛡️ CyberShield - Password Security & Breach Analyzer

**CyberShield** is an advanced, privacy-first Password Security Analyzer, Generator, and Breach Diagnostic suite. It provides real-time password strength scoring, Shannon entropy calculations, character composition breakdown, brute-force crack time matrix, common pattern diagnostics, and k-Anonymity privacy-preserving integration with HaveIBeenPwned (HIBP).

---

## 🌟 Key Features

1. **Interactive Glassmorphism Cyber Dashboard (Web UI)**:
   - Ultra-sleek dark mode interface with neon accents, responsive layout, dynamic progress ring gauges, and real-time visual metrics.
   - **Privacy-Preserving HIBP Breach Checker**: Uses SHA-1 k-Anonymity (only 5-char hash prefix is transmitted; password stays strictly local).
   - **Time-to-Crack Matrix**: Computes brute-force durations across 4 threat scenarios (Online Throttled, Online Unthrottled, GPU Rig, Quantum Supercomputer).
   - **Pattern & Vulnerability Diagnostics**: Automatically detects keyboard walks (`qwerty`, `asdf`), repeated characters (`aaa`), sequential numbers (`1234`), 4-digit years, and weak dictionary matches.
   
2. **Password Generator Suite**:
   - Cryptographically secure random character generator with customizable lengths (8 to 64) and set filters.
   - Passphrase Generator (EFF-inspired human-memorable multi-word combinations).

3. **Batch Security Audit & Export**:
   - Audit lists of credentials by pasting or uploading `.txt` / `.csv` files.
   - Export audit reports directly into structured **CSV** or **JSON** files.

4. **Python CLI & REST API Module**:
   - Full Python standard library analyzer (`password_analyzer.py`).
   - Terminal CLI tool with colorized output (`cli.py`).
   - Flask REST API server (`app.py`).
   - Automated unit test suite (`test_analyzer.py`).

---

## 📁 Project Structure

```
Password security analyzer/
├── index.html                 # Main Cyber Web Dashboard UI
├── styles.css                 # Glassmorphism & Cyberpunk Design System
├── app.js                     # Client-side Analyzer Engine & UI Controller
├── common-passwords.js        # Offline common password dictionary asset
├── password_analyzer.py       # Core Python Password Security Engine
├── cli.py                     # Command-Line Interface tool
├── app.py                     # Flask REST API server
├── test_analyzer.py           # Unit tests suite
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```

---

## 🚀 Quick Start Guide

### Option 1: Web Interface (Zero Setup Required!)
Simply open `index.html` in any web browser:
- Double-click `index.html` or open it with your favorite browser (Chrome, Edge, Firefox, Safari).

---

### Option 2: Python Command Line (CLI)

Run the CLI tool directly with Python:

```bash
# Interactive Mode
python cli.py

# Single Password Analysis
python cli.py -p "P@ssw0rd2024!"

# Export Raw JSON
python cli.py -p "P@ssw0rd2024!" --json

# Batch Audit File
python cli.py --file passwords.txt
```

---

### Option 3: Python Web Server & REST API

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the Python server:
   ```bash
   python app.py
   ```
3. Open in Browser:
   - Visit **http://127.0.0.1:5000/** in your browser to open the Web Dashboard UI.

4. Or test REST API endpoints via `curl` / Postman:
   - **Health check:** `http://127.0.0.1:5000/api/health`
   - **Analyze endpoint:**
     ```bash
     curl -X POST http://127.0.0.1:5000/api/analyze \
       -H "Content-Type: application/json" \
       -d '{"password": "TargetPassword123!"}'
     ```

---

## 🧪 Running Unit Tests

Run unit tests using Python's built-in `unittest`:

```bash
python -m unittest test_analyzer.py
```

---

## 🧮 Mathematical Formulas & Security Principles

### Shannon Entropy ($H$)
$$H = -\sum_{i=1}^{N} p_i \log_2(p_i)$$

Where $p_i$ is the probability of character $i$ appearing in the password string.

### Charset Space Entropy ($E$)
$$E = L \times \log_2(N)$$

Where $L$ is password length and $N$ is total character pool size.

### HIBP k-Anonymity Protocol
1. Calculate SHA-1 Hash of password.
2. Send first 5 characters (Prefix) to `https://api.pwnedpasswords.com/range/{prefix}`.
3. Compare remaining 35 characters (Suffix) locally.
4. **Result:** Password string is NEVER transmitted over the network!

---

## 🛡️ Privacy & Compliance
- **100% Client-Side / Zero Data Collection**: No passwords, hashes, or telemetry are ever stored or transmitted in plain text.
- **NIST SP 800-63B Compliant**: Evaluates passwords based on modern NIST standards emphasizing length, entropy, and breach verification.
