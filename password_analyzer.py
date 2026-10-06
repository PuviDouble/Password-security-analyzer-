import math
import re
import hashlib
import urllib.request
import urllib.error
from typing import Dict, List, Any, Tuple

# Built-in common password subset
COMMON_PASSWORDS_SET = {
    "123456", "password", "123456789", "12345678", "12345", "1234567", "1234", "qwerty",
    "1234567890", "111111", "abc123", "dragon", "admin", "welcome", "monkey", "password1",
    "sunshine", "football", "princess", "charlie", "123321", "iloveyou", "trustno1", "computer",
    "master", "shadow", "superman", "starwars", "batman", "pass123", "solo", "hello",
    "freedom", "whatever", "love", "mustang", "keyboard", "access", "shadow", "baseball",
    "matrix", "cyber", "system", "change", "testing", "letmein", "guest", "root",
    "qwertz", "azerty", "987654321", "654321", "123123", "666666", "7777777", "888888",
    "000000", "password123", "p@ssword", "p@ssw0rd", "pass1234", "admin123", "admin1234"
}

KEYBOARD_WALKS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "qwertzuiop", "azertyuiop"
]

class PasswordAnalyzer:
    """
    Core Password Security Analyzer Engine.
    Provides Shannon entropy, character composition breakdown, pattern detection,
    crack time estimation, and HIBP k-Anonymity breach detection.
    """

    @staticmethod
    def calculate_entropy(pwd: str) -> Dict[str, float]:
        """Calculates Shannon Entropy and Charset Space Entropy."""
        if not pwd:
            return {"shannon": 0.0, "pool_size": 0, "pool_entropy": 0.0}

        pool_size = 0
        if re.search(r'[a-z]', pwd): pool_size += 26
        if re.search(r'[A-Z]', pwd): pool_size += 26
        if re.search(r'[0-9]', pwd): pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', pwd): pool_size += 33

        pool_entropy = len(pwd) * math.log2(pool_size) if pool_size > 0 else 0

        # Shannon Entropy Formula: H = - sum(p * log2(p))
        char_counts = {}
        for char in pwd:
            char_counts[char] = char_counts.get(char, 0) + 1

        shannon = 0.0
        length = len(pwd)
        for count in char_counts.values():
            p = count / length
            shannon -= p * math.log2(p)

        total_shannon = shannon * length

        return {
            "shannon": round(total_shannon, 2),
            "pool_size": pool_size,
            "pool_entropy": round(length * math.log2(pool_size), 2) if pool_size > 0 else 0.0
        }

    @staticmethod
    def get_character_composition(pwd: str) -> Dict[str, Dict[str, Any]]:
        """Calculates character set distribution counts and percentages."""
        length = len(pwd) if len(pwd) > 0 else 1
        lower = len(re.findall(r'[a-z]', pwd))
        upper = len(re.findall(r'[A-Z]', pwd))
        number = len(re.findall(r'[0-9]', pwd))
        symbol = len(re.findall(r'[^a-zA-Z0-9]', pwd))

        return {
            "lowercase": {"count": lower, "percentage": round((lower / length) * 100, 1)},
            "uppercase": {"count": upper, "percentage": round((upper / length) * 100, 1)},
            "numbers": {"count": number, "percentage": round((number / length) * 100, 1)},
            "symbols": {"count": symbol, "percentage": round((symbol / length) * 100, 1)}
        }

    @staticmethod
    def detect_patterns(pwd: str) -> List[Dict[str, str]]:
        """Scans for vulnerabilities, keyboard walks, repeated characters, dates."""
        alerts = []
        lower_pwd = pwd.lower()

        if not pwd:
            return alerts

        # Length diagnostics
        if len(pwd) < 8:
            alerts.append({"type": "danger", "message": "Critically short password (< 8 characters). Instant brute-force risk."})
        elif len(pwd) < 12:
            alerts.append({"type": "warning", "message": "Password length under 12 characters. 14+ recommended."})
        else:
            alerts.append({"type": "success", "message": "Strong length (12+ characters)."})

        # Dictionary match
        if lower_pwd in COMMON_PASSWORDS_SET:
            alerts.append({"type": "danger", "message": "EXACT MATCH in common leaked passwords database!"})

        # Keyboard walks
        for walk in KEYBOARD_WALKS:
            for i in range(len(walk) - 3):
                sub = walk[i:i+4]
                if sub in lower_pwd or sub[::-1] in lower_pwd:
                    alerts.append({"type": "danger", "message": f"Contains sequential keyboard walk ('{sub}')."})
                    break

        # Repeated characters
        if re.search(r'(.)\1{2,}', pwd):
            alerts.append({"type": "warning", "message": "Contains consecutive repeated characters."})

        # Sequential sequence
        if re.search(r'(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg)', lower_pwd):
            alerts.append({"type": "warning", "message": "Contains simple sequential pattern."})

        # Year check
        if re.search(r'(19\d\d|20[0-2]\d)', pwd):
            alerts.append({"type": "warning", "message": "Contains a 4-digit year format."})

        return alerts

    @staticmethod
    def check_hibp_pwned(pwd: str) -> Tuple[bool, int]:
        """
        Queries HaveIBeenPwned API using SHA-1 k-Anonymity protocol.
        Only the first 5 characters of SHA-1 hash are sent.
        Returns: (is_breached, breach_count)
        """
        if not pwd:
            return False, 0

        sha1_hash = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'CyberShield-Password-Analyzer'})
            with urllib.request.urlopen(req, timeout=5) as response:
                lines = response.read().decode('utf-8').splitlines()
                for line in lines:
                    parts = line.split(':')
                    if len(parts) == 2 and parts[0] == suffix:
                        return True, int(parts[1])
            return False, 0
        except Exception:
            # Fallback for offline mode or network error
            return False, 0

    @staticmethod
    def estimate_crack_times(pool_size: int, length: int) -> Dict[str, str]:
        """Calculates time estimates to crack password across various hash rates."""
        if length == 0 or pool_size == 0:
            return {sc: "Instant" for sc in ["online_throttled", "online_unthrottled", "gpu_rig", "quantum"]}

        total_combinations = pool_size ** length
        avg_attempts = total_combinations / 2

        def format_duration(seconds: float) -> str:
            if seconds < 0.001: return "< 1 ms"
            if seconds < 1: return f"{int(seconds * 1000)} ms"
            if seconds < 60: return f"{int(seconds)} seconds"
            if seconds < 3600: return f"{int(seconds / 60)} minutes"
            if seconds < 86400: return f"{int(seconds / 3600)} hours"
            if seconds < 31536000: return f"{int(seconds / 86400)} days"
            years = seconds / 31536000
            if years < 1000: return f"{int(years)} years"
            if years < 1e6: return f"{round(years / 1000, 1)}K years"
            if years < 1e9: return f"{round(years / 1e6, 1)}M years"
            return "Trillions of years"

        return {
            "online_throttled": format_duration(avg_attempts / 10),
            "online_unthrottled": format_duration(avg_attempts / 100),
            "gpu_rig": format_duration(avg_attempts / 100_000_000_000),
            "quantum": format_duration(avg_attempts / 10_000_000_000_000)
        }

    def analyze(self, pwd: str, check_breach: bool = True) -> Dict[str, Any]:
        """Executes complete security audit on target password."""
        entropy = self.calculate_entropy(pwd)
        composition = self.get_character_composition(pwd)
        alerts = self.detect_patterns(pwd)
        
        is_breached, breach_count = (False, 0)
        if check_breach:
            is_breached, breach_count = self.check_hibp_pwned(pwd)

        if is_breached:
            alerts.insert(0, {
                "type": "danger",
                "message": f"CRITICAL: Found in HIBP breach database {breach_count:,} times!"
            })

        # Calculate Overall Score (0-100)
        score = 0
        if pwd and not is_breached:
            score += min(40, len(pwd) * 2.8)
            score += min(40, (entropy["pool_entropy"] / 128) * 40)
            
            variety = sum(1 for k, v in composition.items() if v["count"] > 0)
            score += variety * 5

            for alert in alerts:
                if alert["type"] == "danger": score -= 20
                elif alert["type"] == "warning": score -= 8

        score = max(0, min(100, round(score)))

        # Tier label
        if score < 25: tier = "Very Weak"
        elif score < 50: tier = "Weak"
        elif score < 75: tier = "Moderate"
        elif score < 90: tier = "Strong"
        else: tier = "Extremely Fortified"

        crack_times = self.estimate_crack_times(entropy["pool_size"], len(pwd))

        return {
            "password_length": len(pwd),
            "score": score,
            "rating_tier": tier,
            "entropy": entropy,
            "composition": composition,
            "alerts": alerts,
            "is_breached": is_breached,
            "breach_count": breach_count,
            "crack_times": crack_times
        }
