# Automated Information Gathering and Security Reporting Tool

**Diploma Final Year Project — Cyber Security & Ethical Hacking**

---

## Project Overview

This is a Python-based cybersecurity tool designed for authorized reconnaissance and security assessment. It automatically collects information about a target domain or IP address, analyzes security risks based on open ports and services, and generates a professional multi-format security report.

This project is built for educational purposes as part of a Diploma in Computer Science / Cyber Security & Ethical Hacking final year submission.

---

## Features

| Feature | Description |
|---|---|
| Target Input | Accepts domain name or IP address with validation |
| IP Resolver | Converts domain to IP using socket library |
| DNS Lookup | Fetches A, MX, NS, and TXT records |
| WHOIS Lookup | Retrieves domain registration information |
| Port Scanner | Scans 10 common ports for open services |
| Banner Grabbing | Detects service versions and server info |
| Risk Analysis | Identifies security risks with recommendations |
| Report Generator | Creates TXT, CSV, and JSON reports |

---

## Project Structure

```
cyber_project/
│
├── main.py                  ← Main entry point (run this)
│
├── modules/                 ← All feature modules
│   ├── __init__.py
│   ├── target_input.py      ← User input & validation
│   ├── ip_resolver.py       ← Domain to IP conversion
│   ├── dns_lookup.py        ← DNS record fetching
│   ├── whois_lookup.py      ← WHOIS domain information
│   ├── port_scanner.py      ← Port scanning (TCP connect)
│   ├── banner_grabber.py    ← Service banner detection
│   ├── risk_analysis.py     ← Security risk identification
│   └── report_generator.py  ← TXT, CSV, JSON report creation
│
├── reports/                 ← Generated reports are saved here
│   └── report_<target>_<timestamp>.txt / .csv / .json
│
├── requirements.txt         ← Python library dependencies
└── README.md                ← This file
```

---

## Installation Steps

### Step 1: Install Python
Make sure Python 3.8 or higher is installed.
```
python --version
```

### Step 2: Download/Clone the Project
Place the project folder on your desktop or preferred location.

### Step 3: Open Terminal/Command Prompt
Navigate to the project folder:
```
cd cyber_project
```

### Step 4: Install Required Libraries
```
pip install -r requirements.txt
```

### Step 5: Run the Tool
```
python main.py
```

---

## How to Use

1. Run `python main.py`
2. Enter a target domain (e.g., `example.com`) or IP address
3. Confirm the target
4. Wait for all scans to complete (approx. 30–60 seconds)
5. View results on screen and find reports in the `reports/` folder

---

## Example Output

```
============================================================
   AUTOMATED INFORMATION GATHERING & SECURITY REPORT TOOL
         Final Year Diploma Project - Cyber Security
============================================================

[*] Enter Target Domain or IP Address: example.com
[+] Target Set: example.com
[?] Confirm target? (yes/no): yes

[*] MODULE 1: IP RESOLVER
----------------------------------------
[+] Target     : example.com
[+] IP Address : 93.184.216.34
[+] Status     : Successfully Resolved

[*] MODULE 2: DNS LOOKUP
[+] A Records:
    --> 93.184.216.34
[+] MX Records:
    --> mail.example.com (Priority: 10)
[+] NS Records:
    --> ns1.example.com
    --> ns2.example.com

[*] MODULE 4: PORT SCANNER
[-] Port    21 | CLOSED | FTP
[+] Port    22 | OPEN   | SSH
[-] Port    23 | CLOSED | Telnet
[+] Port    80 | OPEN   | HTTP
[+] Port   443 | OPEN   | HTTPS

[*] MODULE 6: RISK ANALYSIS
[~]   Port 22  | LOW RISK    | SSH Port Open
[!]   Port 80  | LOW RISK    | HTTP Unencrypted
[i]   Port 443 | INFO        | HTTPS (Secure)
```

---

## Ports Scanned

| Port | Service | Risk Level |
|------|---------|------------|
| 21 | FTP | HIGH |
| 22 | SSH | LOW |
| 23 | Telnet | CRITICAL |
| 25 | SMTP | MEDIUM |
| 53 | DNS | MEDIUM |
| 80 | HTTP | LOW |
| 110 | POP3 | MEDIUM |
| 143 | IMAP | MEDIUM |
| 443 | HTTPS | INFO |
| 3306 | MySQL | CRITICAL |

---

## Report Formats

- **TXT** — Human-readable professional security report
- **CSV** — Spreadsheet format for Excel/Google Sheets analysis
- **JSON** — Machine-readable format for further processing

Reports are saved automatically in the `reports/` folder with timestamp in filename.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Core programming language |
| socket | Port scanning, banner grabbing, IP resolution |
| dnspython | DNS record lookups |
| python-whois | WHOIS domain information |
| json | JSON report generation |
| csv | CSV report generation |
| datetime | Timestamps in reports |

---

## Legal Disclaimer

This tool is developed strictly for **educational purposes** as part of a Diploma final year project.

**Only use this tool on:**
- Your own systems
- Systems you have written permission to test
- Lab/practice environments (e.g., Metasploitable, DVWA, HackTheBox)

Unauthorized scanning of systems is **illegal** under the IT Act 2000 (India) and similar laws worldwide. The developer and college are not responsible for any misuse.

---

## Author

- **Name:** [Your Full Name]
- **Roll No:** [Your Roll Number]
- **Branch:** Diploma in Computer Science / Cyber Security
- **College:** [Your College Name]
- **Guide:** [Faculty Guide Name]
- **Year:** 2024–2025
