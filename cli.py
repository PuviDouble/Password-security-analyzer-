#!/usr/bin/env python3
"""
CyberShield CLI - Password Security & Breach Analyzer Command Line Tool
Usage:
    python cli.py -p "TargetPassword123!"
    python cli.py --file passwords.txt --json
    python cli.py --interactive
"""

import sys
import json
import argparse
from password_analyzer import PasswordAnalyzer

# Force UTF-8 stdout encoding if possible for Windows terminal compatibility
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    banner = f"""
{CYAN}{BOLD}=============================================================
  CYBERSHIELD - PASSWORD SECURITY & BREACH ANALYZER CLI
============================================================={RESET}
"""
    print(banner)

def color_score(score: int, label: str) -> str:
    if score < 25: return f"{RED}{BOLD}{score}/100 ({label}){RESET}"
    if score < 50: return f"{YELLOW}{score}/100 ({label}){RESET}"
    if score < 75: return f"{YELLOW}{score}/100 ({label}){RESET}"
    if score < 90: return f"{GREEN}{score}/100 ({label}){RESET}"
    return f"{CYAN}{BOLD}{score}/100 ({label}){RESET}"

def print_report(res: dict, raw_pwd: str):
    print_banner()
    masked = raw_pwd[:2] + "*" * (len(raw_pwd) - 4) + raw_pwd[-2:] if len(raw_pwd) > 4 else "****"
    print(f"Target Password:   {BOLD}{masked}{RESET} (Length: {res['password_length']})")
    print(f"Security Score:    {color_score(res['score'], res['rating_tier'])}")
    print(f"Shannon Entropy:   {CYAN}{res['entropy']['shannon']} bits{RESET} (Pool Entropy: {res['entropy']['pool_entropy']} bits)")
    print(f"Charset Space:     {res['entropy']['pool_size']} possible characters")
    print(f"HIBP Breach Check: {'HIBP Breached (' + str(res['breach_count']) + ' times!)' if res['is_breached'] else GREEN + 'Safe (0 Breaches Found)' + RESET}")

    print(f"\n{BOLD}Character Composition Breakdown:{RESET}")
    comp = res['composition']
    print(f"  * Lowercase: {comp['lowercase']['count']} ({comp['lowercase']['percentage']}%)")
    print(f"  * Uppercase: {comp['uppercase']['count']} ({comp['uppercase']['percentage']}%)")
    print(f"  * Numbers:   {comp['numbers']['count']} ({comp['numbers']['percentage']}%)")
    print(f"  * Symbols:   {comp['symbols']['count']} ({comp['symbols']['percentage']}%)")

    print(f"\n{BOLD}Time-to-Crack Estimates:{RESET}")
    cracks = res['crack_times']
    print(f"  * Online Throttled (10 req/s):         {CYAN}{cracks['online_throttled']}{RESET}")
    print(f"  * Online Unthrottled (100 req/s):       {CYAN}{cracks['online_unthrottled']}{RESET}")
    print(f"  * Offline GPU Rig (100B hashes/s):      {CYAN}{cracks['gpu_rig']}{RESET}")
    print(f"  * Quantum Supercomputer (10T req/s):    {CYAN}{cracks['quantum']}{RESET}")

    print(f"\n{BOLD}Vulnerability Diagnostics:{RESET}")
    if not res['alerts']:
        print(f"  {GREEN}[+] No vulnerabilities detected.{RESET}")
    else:
        for alert in res['alerts']:
            icon = f"{RED}[X]{RESET}" if alert['type'] == 'danger' else f"{YELLOW}[!]{RESET}" if alert['type'] == 'warning' else f"{GREEN}[+]{RESET}"
            print(f"  {icon} {alert['message']}")
    print("\n" + "=" * 61 + "\n")

def main():
    parser = argparse.ArgumentParser(description="CyberShield Password Security & Breach Analyzer")
    parser.add_argument("-p", "--password", type=str, help="Password string to analyze")
    parser.add_argument("-f", "--file", type=str, help="Path to text file containing list of passwords to audit")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive prompt mode")
    parser.add_argument("-j", "--json", action="store_true", help="Output raw JSON analysis result")
    parser.add_argument("--no-hibp", action="store_true", help="Skip online HaveIBeenPwned API check")

    args = parser.parse_args()
    analyzer = PasswordAnalyzer()

    if args.password:
        res = analyzer.analyze(args.password, check_breach=not args.no_hibp)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_report(res, args.password)
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            results = []
            for pwd in passwords:
                r = analyzer.analyze(pwd, check_breach=not args.no_hibp)
                r['password'] = pwd
                results.append(r)

            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_banner()
                print(f"Audited {len(passwords)} passwords from file: {args.file}\n")
                for r in results:
                    masked = r['password'][:2] + "*" * (len(r['password']) - 4) + r['password'][-2:] if len(r['password']) > 4 else "****"
                    print(f"[{r['score']}/100 - {r['rating_tier']}] {masked} (Entropy: {r['entropy']['pool_entropy']} bits)")
        except Exception as e:
            print(f"{RED}Error reading file '{args.file}': {e}{RESET}")
            sys.exit(1)
    elif args.interactive or len(sys.argv) == 1:
        print_banner()
        while True:
            try:
                user_pwd = input(f"{CYAN}Enter password to analyze (or 'q' to quit): {RESET}").strip()
                if user_pwd.lower() in ('q', 'exit', 'quit'):
                    print("Exiting CyberShield CLI. Stay secure!")
                    break
                if not user_pwd:
                    continue
                res = analyzer.analyze(user_pwd, check_breach=not args.no_hibp)
                print_report(res, user_pwd)
            except KeyboardInterrupt:
                print("\nSession terminated.")
                break

if __name__ == "__main__":
    main()
