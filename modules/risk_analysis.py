# ============================================================
# MODULE: risk_analysis.py
# PURPOSE: Analyzes scan results and identifies security risks
#          based on open ports, banners, and configurations
# ============================================================


# Risk database: defines risk level and description for each port
# Risk Levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
PORT_RISKS = {
    21: {
        "level": "HIGH",
        "risk": "FTP Port Open",
        "description": (
            "FTP (File Transfer Protocol) transfers data in PLAINTEXT. "
            "Credentials and files can be intercepted using packet sniffing. "
            "Anonymous FTP access may also be enabled."
        ),
        "recommendation": (
            "Disable FTP and use SFTP or SCP instead. "
            "If FTP is required, use FTPS (FTP over SSL). "
            "Restrict FTP access by IP and disable anonymous login."
        )
    },
    22: {
        "level": "LOW",
        "risk": "SSH Port Open",
        "description": (
            "SSH (Secure Shell) provides encrypted remote access. "
            "While generally secure, weak passwords or old SSH versions "
            "can be exploited through brute-force attacks."
        ),
        "recommendation": (
            "Use SSH key-based authentication instead of passwords. "
            "Disable root login via SSH. "
            "Keep OpenSSH updated. Consider changing default port 22."
        )
    },
    23: {
        "level": "CRITICAL",
        "risk": "Telnet Port Open",
        "description": (
            "Telnet transmits ALL data including passwords in PLAINTEXT. "
            "This is a critical security vulnerability. Anyone on the "
            "same network can capture the entire session using Wireshark."
        ),
        "recommendation": (
            "IMMEDIATELY disable Telnet. "
            "Replace Telnet with SSH for all remote access. "
            "There is NO secure way to use Telnet in production."
        )
    },
    25: {
        "level": "MEDIUM",
        "risk": "SMTP Port Open",
        "description": (
            "SMTP (Simple Mail Transfer Protocol) is used to send emails. "
            "An open SMTP server can be abused as an Open Relay, "
            "allowing spammers to send spam through your server."
        ),
        "recommendation": (
            "Ensure SMTP relay is restricted to authorized users only. "
            "Implement SPF, DKIM, and DMARC email authentication. "
            "Use TLS/SSL for SMTP connections."
        )
    },
    53: {
        "level": "MEDIUM",
        "risk": "DNS Port Open",
        "description": (
            "An open DNS port can be abused for DNS Amplification attacks, "
            "which are a type of DDoS attack. Zone transfer attacks may also "
            "be possible if AXFR requests are not restricted."
        ),
        "recommendation": (
            "Restrict DNS zone transfers to authorized name servers only. "
            "Implement rate limiting on DNS queries. "
            "Use a firewall to restrict DNS access to trusted clients."
        )
    },
    80: {
        "level": "LOW",
        "risk": "HTTP Port Open (Unencrypted Web)",
        "description": (
            "HTTP traffic is transmitted in PLAINTEXT. "
            "User credentials and sensitive data can be intercepted. "
            "The site may be vulnerable to Man-in-the-Middle attacks."
        ),
        "recommendation": (
            "Force HTTPS on all connections using HTTP → HTTPS redirect. "
            "Implement HSTS (HTTP Strict Transport Security). "
            "Obtain and install a valid SSL/TLS certificate."
        )
    },
    110: {
        "level": "MEDIUM",
        "risk": "POP3 Port Open",
        "description": (
            "POP3 without SSL transmits email credentials in plaintext. "
            "Email contents can be intercepted during transmission."
        ),
        "recommendation": (
            "Use POP3S (POP3 over SSL, Port 995) instead. "
            "Disable unencrypted POP3 access entirely."
        )
    },
    143: {
        "level": "MEDIUM",
        "risk": "IMAP Port Open",
        "description": (
            "IMAP without SSL transmits email credentials in plaintext. "
            "This allows interception of email content and login credentials."
        ),
        "recommendation": (
            "Use IMAPS (IMAP over SSL, Port 993) instead. "
            "Disable unencrypted IMAP access."
        )
    },
    443: {
        "level": "INFO",
        "risk": "HTTPS Port Open (Secure)",
        "description": (
            "HTTPS uses SSL/TLS encryption for secure communication. "
            "However, weak cipher suites, expired SSL certificates, or "
            "misconfigured TLS settings can still create vulnerabilities."
        ),
        "recommendation": (
            "Use TLS 1.2 or higher (disable TLS 1.0 and 1.1). "
            "Ensure SSL certificate is valid and not expired. "
            "Check for weak cipher suites using SSL Labs (ssllabs.com)."
        )
    },
    3306: {
        "level": "CRITICAL",
        "risk": "MySQL Database Port Open to Internet",
        "description": (
            "A publicly accessible MySQL database is EXTREMELY DANGEROUS. "
            "Attackers can attempt brute-force attacks on the database. "
            "Database breaches can expose ALL user and application data."
        ),
        "recommendation": (
            "IMMEDIATELY close MySQL port from public internet. "
            "MySQL should ONLY be accessible from localhost or private network. "
            "Use firewall rules to block port 3306 from external access. "
            "Use strong passwords and limit database user privileges."
        )
    }
}

# Risk level ordering for sorting (higher = more severe)
RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def analyze_risks(port_results):
    """
    Takes port scan results and matches open ports with
    their known security risks from the PORT_RISKS database.

    Returns a list of risk findings sorted by severity.
    """

    print("\n[*] MODULE 6: RISK ANALYSIS")
    print("-" * 40)
    print("[*] Analyzing open ports for security risks...")
    print()

    risk_findings = []   # All identified risks
    risk_summary = {     # Count of each severity level
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    # Check each open port against risk database
    for port_info in port_results:
        if port_info["status"] == "Open":
            port = port_info["port"]

            if port in PORT_RISKS:
                # Get the risk info for this port
                risk_info = PORT_RISKS[port].copy()
                risk_info["port"] = port
                risk_info["service"] = port_info["service"]

                risk_findings.append(risk_info)
                risk_summary[risk_info["level"]] += 1

                # Print finding with color-coded indicators
                level = risk_info["level"]
                indicator = {
                    "CRITICAL": "[!!!]",
                    "HIGH":     "[!!] ",
                    "MEDIUM":   "[!]  ",
                    "LOW":      "[~]  ",
                    "INFO":     "[i]  "
                }.get(level, "[?]  ")

                print(f"{indicator} Port {port} | {level} RISK | {risk_info['risk']}")
                print(f"       {risk_info['description'][:80]}...")
                print()

    # Sort findings by severity (Critical first)
    risk_findings.sort(
        key=lambda x: RISK_ORDER.get(x["level"], 0),
        reverse=True
    )

    # Print summary
    print("-" * 40)
    print("[*] RISK SUMMARY:")
    print(f"    CRITICAL : {risk_summary['CRITICAL']} finding(s)")
    print(f"    HIGH     : {risk_summary['HIGH']} finding(s)")
    print(f"    MEDIUM   : {risk_summary['MEDIUM']} finding(s)")
    print(f"    LOW      : {risk_summary['LOW']} finding(s)")
    print(f"    INFO     : {risk_summary['INFO']} finding(s)")

    total = sum(risk_summary.values())
    print(f"\n[+] Total Risk Findings: {total}")

    if risk_summary["CRITICAL"] > 0:
        print("\n[!!!] CRITICAL RISKS DETECTED! Immediate action required.")
    elif risk_summary["HIGH"] > 0:
        print("\n[!!]  HIGH RISKS DETECTED! Review and remediate soon.")
    elif total == 0:
        print("\n[+]   No major risks detected from scanned ports.")

    return risk_findings, risk_summary
