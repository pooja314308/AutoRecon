# ============================================================
# MODULE: port_scanner.py
# PURPOSE: Scans common ports on the target to detect which
#          services are open and accessible
# ============================================================

import socket   # For network connections
import time     # For timing and delay


# Common ports and their associated services
# These are the most important ports in security scanning
COMMON_PORTS = {
    21:   "FTP (File Transfer Protocol)",
    22:   "SSH (Secure Shell)",
    23:   "Telnet (Unencrypted Remote Login)",
    25:   "SMTP (Email Sending)",
    53:   "DNS (Domain Name System)",
    80:   "HTTP (Web Server)",
    110:  "POP3 (Email Receiving)",
    143:  "IMAP (Email Access)",
    443:  "HTTPS (Secure Web Server)",
    3306: "MySQL (Database)"
}


def scan_ports(target, ip_address=None):
    """
    Scans a list of common ports on the target.
    For each port, tries to connect and checks if it's open.

    Returns a list of dictionaries with port scan results.
    """

    print("\n[*] MODULE 4: PORT SCANNER")
    print("-" * 40)
    print("[*] Scanning common ports... (This may take a few seconds)")
    print()

    # Use IP if available, else use target directly
    scan_target = ip_address if ip_address else target

    scan_results = []  # Store all port results here

    for port, service_name in COMMON_PORTS.items():

        port_data = {
            "port": port,
            "service": service_name,
            "status": "Closed",
            "error": None
        }

        try:
            # Create a new TCP socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set timeout to 1 second (don't wait too long)
            sock.settimeout(1)

            # Try to connect to the port
            # connect_ex() returns 0 if connection is successful
            result = sock.connect_ex((scan_target, port))

            if result == 0:
                # Port is OPEN - connection was successful
                port_data["status"] = "Open"
                print(f"[+] Port {port:5d} | OPEN   | {service_name}")
            else:
                # Port is CLOSED or FILTERED
                port_data["status"] = "Closed"
                print(f"[-] Port {port:5d} | CLOSED | {service_name}")

            # Always close the socket after checking
            sock.close()

        except socket.timeout:
            # Connection timed out = port is filtered/blocked
            port_data["status"] = "Filtered"
            port_data["error"] = "Timeout"
            print(f"[?] Port {port:5d} | FILTERED | {service_name}")

        except socket.error as e:
            # Some other network error occurred
            port_data["status"] = "Error"
            port_data["error"] = str(e)
            print(f"[!] Port {port:5d} | ERROR | {service_name} - {e}")

        scan_results.append(port_data)

        # Small delay to avoid aggressive scanning
        time.sleep(0.1)

    # Count open ports for summary
    open_ports = [p for p in scan_results if p["status"] == "Open"]
    print(f"\n[+] Scan Complete: {len(open_ports)} open port(s) found out of {len(COMMON_PORTS)} scanned.")

    return scan_results
