    #!/usr/bin/env python3
"""
PhishShield AI — Backend REST API & Static Server
A zero-dependency Python server powering real-time anti-phishing heuristics,
lexical domain entropy analysis, and social engineering threat detection.
"""

import http.server
import socketserver
import json
import urllib.parse
import re
import math
import os
import sys
from datetime import datetime

PORT = 8000

# High-Risk Top Level Domains (APWG & Spamhaus threat data)
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'cam', 'click', 'work',
    'rest', 'buzz', 'fit', 'kim', 'surf', 'icu', 'monster', 'country',
    'link', 'stream', 'download', 'win', 'vip', 'bid', 'loan', 'racing'
}

# Monitored High-Target Brands
MONITORED_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'netflix', 'amazon',
    'chase', 'wellsfargo', 'bankofamerica', 'binance', 'metamask',
    'coinbase', 'steam', 'discord', 'facebook', 'instagram', 'whatsapp',
    'twitter', 'linkedin', 'dropbox', 'dhl', 'fedex', 'usps'
]

# Homoglyph character lookalikes
HOMOGLYPH_CHARS = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
}

# Suspicious credential solicitation keywords
PHISHING_KEYWORDS = [
    'verify', 'verification', 'secure', 'account-update', 'login', 'signin',
    'banking', 'wallet-connect', 'seed-phrase', 'suspended', 'reactivate',
    'claim-bonus', 'security-check', 'authorize', 'confirm-identity',
    'billing-update', 'unauthorized-access', 'kyc-approval'
]

def calculate_shannon_entropy(s: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def analyze_url_heuristics(raw_url: str) -> dict:
    """Server-side deep forensic evaluation of suspicious URLs with malformed URL validation."""
    raw_url = raw_url.strip()
    if not raw_url:
        return {"error": "Target URL cannot be empty."}

    is_invalid = False
    invalid_reasons = []

    # Check for scheme anomalies
    scheme_match = re.match(r'^([a-zA-Z0-9+.-]+)://', raw_url)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in ('http', 'https'):
            is_invalid = True
            if scheme in ('htp', 'htps', 'httpz', 'htttp', 'htt'):
                invalid_reasons.append(f"Typo or malformed protocol scheme '{scheme}://' (PhishShield requires standard 'http://' or 'https://').")
            else:
                invalid_reasons.append(f"Unsupported/unsafe URI protocol scheme '{scheme}://'.")
    elif re.match(r'^[a-zA-Z0-9]+:/[^/]', raw_url):
        is_invalid = True
        invalid_reasons.append("Malformed protocol delimiter (missing dual forward slashes '//').")

    has_protocol = bool(re.match(r'^[a-zA-Z0-9+.-]+://', raw_url))
    parse_url = raw_url if has_protocol else 'http://' + raw_url

    parsed = None
    try:
        parsed = urllib.parse.urlparse(parse_url)
    except Exception as e:
        is_invalid = True
        invalid_reasons.append(f"RFC 3986 parse failure: {str(e)}")

    hostname = (parsed.hostname or '').lower() if parsed else ''
    full_path = (((parsed.path or '') + ('?' + parsed.query if parsed and parsed.query else ''))).lower() if parsed else ''

    if not hostname:
        is_invalid = True
        invalid_reasons.append("Missing host authority or invalid domain name syntax.")
    else:
        if '..' in hostname:
            is_invalid = True
            invalid_reasons.append("Consecutive dots ('..') detected in domain structure.")
        if any(c in hostname for c in [' ', '<', '>', '"', '%', '$', '^', '{', '}', '|', '\\']):
            is_invalid = True
            invalid_reasons.append("Illegal characters or unescaped control symbols in hostname.")

        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
        if not is_ip and hostname != 'localhost':
            if '.' not in hostname:
                is_invalid = True
                invalid_reasons.append("Hostname lacks a Top-Level Domain (TLD) extension (e.g. .com, .org, .net).")
            else:
                tld_candidate = hostname.split('.')[-1]
                if not re.match(r'^[a-z]{2,24}$', tld_candidate):
                    is_invalid = True
                    invalid_reasons.append(f"Invalid or corrupted Top-Level Domain syntax ('.{tld_candidate}').")

    if is_invalid:
        factors = []
        for reason in invalid_reasons:
            factors.append({
                "severity": "invalid",
                "title": "Malformed URI / Hostname Syntax",
                "desc": reason
            })
        factors.append({
            "severity": "critical",
            "title": "Parser Evasion / Exploit Probe Hazard",
            "desc": "Adversaries often weaponize syntactically broken URLs to induce parser differentials between security filters and target browser parsers."
        })
        return {
            "isInvalid": True,
            "url": raw_url,
            "hostname": hostname or "INVALID_HOST",
            "tld": "INVALID",
            "entropy": 0.0,
            "threatScore": 0,
            "verdict": "INVALID / MALFORMED URL",
            "verdictClass": "invalid",
            "factors": factors,
            "hasHomoglyph": False,
            "detectedBrand": "None",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "backend": "PhishShield Python Heuristic Engine v2.4"
        }

    factors = []
    threat_score = 0

    # 1. Transport Protocol Security
    if parsed.scheme.lower() == 'http':
        threat_score += 15
        factors.append({
            "severity": "medium",
            "title": "Insecure HTTP Transport Protocol",
            "desc": "Transmits plaintext data without SSL/TLS encryption. Genuine portals enforce HTTPS."
        })
    elif parsed.scheme.lower() == 'https':
        factors.append({
            "severity": "safe",
            "title": "Encrypted HTTPS Protocol Active",
            "desc": "Valid TLS transport layer present."
        })

    # 2. IP Hostname Check
    is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
    if is_ip:
        threat_score += 40
        factors.append({
            "severity": "critical",
            "title": "Raw IP Hostname Detected",
            "desc": f"Host is directly addressed as an IP ({hostname}), characteristic of evasive fast-flux servers."
        })

    # 3. TLD Analysis
    domain_parts = hostname.split('.')
    tld = domain_parts[-1] if len(domain_parts) > 1 else ''
    if tld in SUSPICIOUS_TLDS:
        threat_score += 25
        factors.append({
            "severity": "critical",
            "title": f"High-Risk Top Level Domain (.{tld})",
            "desc": f"The '.{tld}' extension exhibits abnormal rates of malicious spam and phishing abuse."
        })

    # 4. Subdomain Stacking
    if len(domain_parts) >= 4:
        threat_score += 20
        factors.append({
            "severity": "critical",
            "title": "Subdomain Stacking / Mobile Deception",
            "desc": f"Domain contains {len(domain_parts)} hierarchy levels, commonly used to hide fake roots on narrow mobile screens."
        })

    # 5. Homograph & Punycode Attack
    has_homoglyph = any(char in hostname for char in HOMOGLYPH_CHARS.keys())
    is_punycode = hostname.startswith('xn--') or '.xn--' in hostname
    if has_homoglyph or is_punycode:
        threat_score += 45
        factors.append({
            "severity": "critical",
            "title": "Homograph / IDN Punycode Character Spoofing",
            "desc": "Contains non-ASCII lookalike characters designed to deceptively impersonate legitimate brands."
        })

    # 6. Target Brand Spoofing Check
    detected_brand = None
    apex_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
    for brand in MONITORED_BRANDS:
        if brand in hostname:
            if apex_domain not in (f"{brand}.com", f"{brand}.org", f"{brand}.net"):
                threat_score += 35
                detected_brand = brand.upper()
                factors.append({
                    "severity": "critical",
                    "title": f"Target Brand Impersonation ({brand.upper()})",
                    "desc": f"Brand name '{brand}' appears in host, but registered root domain is '{apex_domain}'."
                })
                break
            else:
                detected_brand = f"{brand.upper()} (Verified Apex)"

    # 7. Domain Shannon Entropy
    domain_label = domain_parts[0] if domain_parts else hostname
    entropy = calculate_shannon_entropy(domain_label)
    if entropy > 3.75 and len(domain_label) >= 8:
        threat_score += 20
        factors.append({
            "severity": "medium",
            "title": f"Elevated Shannon Entropy ({entropy} bits)",
            "desc": "High randomness score suggests algorithmic generation (DGA) or automated campaign domains."
        })

    # 8. Authority Splitting with '@'
    if '@' in raw_url:
        threat_score += 30
        factors.append({
            "severity": "critical",
            "title": "Deceptive '@' Authority Splitting",
            "desc": "Uses '@' userinfo syntax to redirect visitors away from the apparent leading hostname."
        })

    # 9. Credential Solicitation Keywords in Path
    matched_kws = [kw for kw in PHISHING_KEYWORDS if kw in full_path or kw in hostname]
    if matched_kws:
        threat_score += min(len(matched_kws) * 10, 25)
        factors.append({
            "severity": "critical" if len(matched_kws) > 1 else "medium",
            "title": "Urgent Credential Keywords in Path",
            "desc": f"Detected harvesting tokens: {', '.join(matched_kws[:4])}."
        })

    # Cap score
    threat_score = min(max(threat_score, 0), 100)
    if not any(f['severity'] != 'safe' for f in factors):
        threat_score = 5
        factors.append({
            "severity": "safe",
            "title": "Clean Architectural Baseline",
            "desc": "No homoglyphs, brand spoofing or known high-risk TLD signals detected."
        })

    if threat_score >= 65:
        verdict = "CRITICAL PHISHING HAZARD"
        verdict_class = "danger"
    elif threat_score >= 35:
        verdict = "SUSPICIOUS / ELEVATED CAUTION"
        verdict_class = "warning"
    else:
        verdict = "BENIGN / LOW RISK"
        verdict_class = "safe"

    return {
        "url": raw_url,
        "hostname": hostname,
        "tld": f".{tld}" if tld else "N/A",
        "entropy": entropy,
        "threatScore": threat_score,
        "verdict": verdict,
        "verdictClass": verdict_class,
        "factors": factors,
        "hasHomoglyph": has_homoglyph or is_punycode,
        "detectedBrand": detected_brand or "None",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "backend": "PhishShield Python Heuristic Engine v2.4"
    }

def analyze_email_heuristics(body_text: str, sender_text: str = "") -> dict:
    """Server-side NLP evaluation of coercive social engineering cues."""
    text = (body_text + " " + sender_text).lower()
    factors = []
    threat_score = 0

    urgency_terms = [
        'within 24 hours', 'immediate action required', 'account suspended',
        'unauthorized login', 'final warning', 'immediately', 'will be closed',
        'security breach', 'unusual activity detected'
    ]
    matched_urgency = [term for term in urgency_terms if term in text]
    if matched_urgency:
        threat_score += 30
        factors.append({
            "severity": "critical",
            "title": "Manufactured Urgency & Panic",
            "desc": f"Contains psychological pressure phrases: '{', '.join(matched_urgency[:2])}'."
        })

    cred_terms = [
        'verify your password', 'enter your seed phrase', 'confirm your pin',
        'update billing info', 'provide your ssn', 're-authenticate'
    ]
    matched_cred = [term for term in cred_terms if term in text]
    if matched_cred:
        threat_score += 35
        factors.append({
            "severity": "critical",
            "title": "Credential Solicitation",
            "desc": f"Requests confidential authentication secrets: '{', '.join(matched_cred)}'."
        })

    finance_terms = [
        'won $', 'wire transfer', 'cryptocurrency reward', 'lottery winner',
        'urgent payment', 'invoice attached', 'gift card'
    ]
    matched_finance = [term for term in finance_terms if term in text]
    if matched_finance:
        threat_score += 25
        factors.append({
            "severity": "medium",
            "title": "Financial Bait / BEC Wire Indicator",
            "desc": f"Mentions unverified payouts, transfers or gift cards: '{', '.join(matched_finance)}'."
        })

    generic_terms = ['dear customer', 'dear user', 'dear account holder', 'dear client']
    has_generic = any(term in text for term in generic_terms)
    if has_generic:
        threat_score += 15
        factors.append({
            "severity": "medium",
            "title": "Impersonal Impostor Greeting",
            "desc": "Message uses generic greeting without recipient's registered name."
        })

    threat_score = min(max(threat_score, 0), 100)
    if not factors:
        threat_score = 5
        factors.append({
            "severity": "safe",
            "title": "Clean Communication Baseline",
            "desc": "No coercive urgency or credential solicitation indicators identified."
        })

    verdict = "BENIGN / NORMAL"
    verdict_class = "safe"
    if threat_score >= 60:
        verdict = "HIGH-RISK SOCIAL ENGINEERING PHISHING"
        verdict_class = "danger"
    elif threat_score >= 30:
        verdict = "SUSPICIOUS / ELEVATED PRESSURE"
        verdict_class = "warning"

    return {
        "threatScore": threat_score,
        "verdict": verdict,
        "verdictClass": verdict_class,
        "factors": factors,
        "urgencyScore": f"{min(len(matched_urgency) * 25, 100)}%",
        "hasCredBait": "DETECTED" if matched_cred else "NONE",
        "hasFinanceBait": "DETECTED" if matched_finance else "NONE",
        "hasGenericGreeting": "YES" if has_generic else "NO",
        "backend": "PhishShield Python NLP Engine v2.4"
    }


class PhishShieldRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP Server handling static files and REST API endpoints."""

    def end_headers(self):
        # Enable CORS for full flexibility
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self.path = '/DETECTION.html'
            return super().do_GET()

        elif self.path == '/api/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "status": "online",
                "engine": "PhishShield AI Python Engine v2.4",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
            return

        elif self.path == '/api/threat-stream':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            stream = [
                {"type": "HOMOGRAPH", "domain": "g00gle-accounts-recovery.xyz", "country": "RU", "target": "Google"},
                {"type": "CRYPTO PHISH", "domain": "connect-metamask-web3-sync.top", "country": "CN", "target": "MetaMask"},
                {"type": "BANKING BEC", "domain": "secure-wellsfargo-update.online", "country": "US", "target": "Wells Fargo"},
                {"type": "QUISHING QR", "domain": "ev-charger-free-charge.click", "country": "DE", "target": "ChargePoint"}
            ]
            self.wfile.write(json.dumps(stream).encode('utf-8'))
            return

        super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_length)

        try:
            payload = json.loads(post_body.decode('utf-8')) if post_body else {}
        except Exception:
            payload = {}

        if self.path == '/api/scan-url':
            url = payload.get('url', '')
            result = analyze_url_heuristics(url)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        elif self.path == '/api/scan-email':
            body = payload.get('body', '')
            sender = payload.get('sender', '')
            result = analyze_email_heuristics(body, sender)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        self.send_response(404)
        self.end_headers()


def run_server():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), PhishShieldRequestHandler) as httpd:
        print(f"============================================================")
        print(f"  🛡️ PhishShield AI — Hybrid Cyber Defense Server Active")
        print(f"  🌐 Local Portal: http://localhost:{PORT}")
        print(f"  ⚡ REST API Endpoints:")
        print(f"     - POST /api/scan-url")
        print(f"     - POST /api/scan-email")
        print(f"     - GET  /api/health")
        print(f"============================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down PhishShield server...")
            sys.exit(0)

if __name__ == '__main__':
    run_server()
