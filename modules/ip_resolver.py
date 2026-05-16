# ============================================================
# MODULE: ip_resolver.py
# PURPOSE: Converts a domain name into its IP address
#          using Python's built-in socket library
# ============================================================

import socket  # Used for network-related operations


def resolve_ip(target):
    """
    Takes a domain name or IP address as input.
    If it's a domain, resolves it to an IP address.
    Returns a dictionary with the result.
    """

    print("\n[*] MODULE 1: IP RESOLVER")
    print("-" * 40)

    result = {
        "target": target,
        "ip_address": None,
        "status": "Unknown",
        "error": None
    }

    try:
        # socket.gethostbyname() converts domain → IP
        ip = socket.gethostbyname(target)

        result["ip_address"] = ip
        result["status"] = "Resolved"

        print(f"[+] Target     : {target}")
        print(f"[+] IP Address : {ip}")
        print(f"[+] Status     : Successfully Resolved")

    except socket.gaierror as e:
        # This error occurs when domain cannot be resolved
        result["status"] = "Failed"
        result["error"] = str(e)

        print(f"[-] Could not resolve IP for: {target}")
        print(f"[-] Error: {e}")

    return result
