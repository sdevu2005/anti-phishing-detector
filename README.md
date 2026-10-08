# 🛡️ PhishShield AI — Anti-Phishing Cyber Defense Suite

An ultra-modern, high-fidelity Anti-Phishing detection platform featuring a futuristic Cyber Operations Center dashboard, real-time forensic heuristics, and hybrid dual-engine architecture.

---

## 🚀 Quick Start Guide

You have **two seamless ways** to use this system:

### Option 1: Zero-Setup Standalone Browser Mode (Instant)
1. Simply double-click `DETECTION.html` (or `index.html`) in any browser (Chrome, Edge, Firefox, Brave).
2. The entire client-side **Neural Heuristic Engine** will execute directly in your browser with no installation, dependencies, or server setup required.

### Option 2: Dedicated Python REST API Backend
1. Open terminal in this folder and start the backend server:
   ```powershell
   python server.py
   ```
2. Open [http://localhost:8000](http://localhost:8000) in your browser.
3. The dashboard will automatically detect the server and display:
   `PYTHON REST API: CONNECTED (:8000)`

---

## ✨ Features & Capabilities

### 🌐 1. Deep URL & Domain Forensic Inspector
- **Shannon Entropy Calculation**: Computes mathematical character randomness to detect algorithmic DGA domains and obfuscated URLs.
- **Homoglyph & Punycode Attack Detection**: Identifies deceptive Cyrillic/Greek lookalikes (`g00gle.com`, `paypa1.com`, `xn--...`).
- **Brand Typo-Squatting Engine**: Detects impersonation of 20+ major targets (`PayPal`, `Google`, `Chase`, `MetaMask`, `Binance`, `Netflix`, etc.).
- **High-Risk TLD Intelligence**: Flags abusive top-level domains (`.xyz`, `.top`, `.tk`, `.cam`, `.click`, `.buzz`).
- **Authority Splitting**: Identifies URL tricks that use `@` characters to hijack browser destination routing.
- **Subdomain Stacking & IP Hosts**: Warns against multi-level domain spoofs and raw numerical IPs.

### ✉️ 2. Email & SMS NLP Social Engineering Analyzer
- **Psychological Pressure Detector**: Catches artificial panic and urgent deadlines (*"within 24 hours"*, *"account suspended immediately"*).
- **Credential Harvesting Sniffer**: Spots secret/password/seed-phrase solicitations.
- **Financial & BEC Bait**: Flags unverified wire transfers, fake invoices, and gift card fraud.
- **Origin Domain Cross-Check**: Validates sender address legitimacy.

### 📱 3. Quishing (QR Phishing) Scanner & Decoder
- Drag-and-drop or upload suspect QR code images.
- Unpacks embedded URL redirects and performs instant safety checks before scanning on mobile phones.

### 📡 4. Live Global Threat Feed
- Real-time simulated zero-day phishing interception stream with honeypot origin telemetry.

### 🎓 5. Phish Awareness Academy (Interactive Quiz)
- Gamified cybersecurity quiz assessing knowledge of real-world phishing vectors with instant scoring and explanations.

---

## 🎨 Visual Aesthetics & Audio Feedback
- **Tactical Dark Cyberpunk Palette**: Obsidian deep navy base, cyber cyan (`#00f2fe`), neon emerald (`#00f59b`), amber, and glowing crimson (`#ff3366`).
- **Interactive SVG Threat Gauge**: Animated circular meter with real-time risk scoring (0–100%).
- **Web Audio API Tactical Sound Engine**: Subtle synthesizer audio cues for scans, alerts, and successes (toggleable ON/OFF).
- **Responsive Glassmorphism**: Frosted glass panels with glowing cyber borders and smooth animations.
