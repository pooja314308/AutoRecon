# ============================================================
# MODULE: target_input.py
# PURPOSE: Accepts and validates the target domain or IP
#          entered by the user
# ============================================================

import re  # Regular expressions for validation


def get_target():
    """
    Displays a welcome banner and asks the user to enter
    a domain name or IP address as the scan target.
    Returns the cleaned target string.
    """

    print("=" * 60)
    print("   AUTOMATED INFORMATION GATHERING & SECURITY REPORT TOOL")
    print("         Final Year Diploma Project - Cyber Security")
    print("=" * 60)
    print()
    print("  This tool will perform:")
    print("  [1] IP Resolution       [2] DNS Lookup")
    print("  [3] WHOIS Lookup        [4] Port Scanning")
    print("  [5] Banner Grabbing     [6] Risk Analysis")
    print("  [7] Report Generation")
    print()
    print("-" * 60)

    while True:
        # Ask user to enter target
        target = input("\n[*] Enter Target Domain or IP Address: ").strip()

        # Check if input is not empty
        if not target:
            print("[!] Error: No target entered. Please try again.")
            continue

        # Remove http:// or https:// if user accidentally added it
        target = target.replace("https://", "").replace("http://", "")

        # Remove trailing slashes
        target = target.rstrip("/")

        # Basic check: must have at least one dot (for domain) or be an IP
        if "." not in target:
            print("[!] Error: Invalid domain or IP. Please enter a valid target.")
            continue

        # If valid, confirm the target with the user
        print(f"\n[+] Target Set: {target}")
        confirm = input("[?] Confirm target? (yes/no): ").strip().lower()

        if confirm in ["yes", "y"]:
            print(f"\n[+] Starting scan on: {target}")
            print("-" * 60)
            return target
        else:
            print("[*] Let's try again.\n")
