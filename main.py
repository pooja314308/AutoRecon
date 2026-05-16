#!/usr/bin/env python3
# ============================================================
# 
#
# DESCRIPTION:
#   This is the main entry point of the project.
#   It calls each module in sequence:
#   1. Get target input from user
#   2. Resolve IP address
#   3. Perform DNS lookup
#   4. Perform WHOIS lookup
#   5. Scan ports
#   6. Grab banners
#   7. Analyze risks
#   8. Generate reports
#
# ── Standard Library Imports ──────────────────────────────
import sys          # For system operations (exit, version check)
import time         # For timing the scan
from datetime import datetime  # For timestamps

# ── Custom Module Imports ─────────────────────────────────
# Each module is in the 'modules/' folder
from modules.target_input    import get_target
from modules.ip_resolver     import resolve_ip
from modules.dns_lookup      import get_dns_records
from modules.whois_lookup    import get_whois_info
from modules.port_scanner    import scan_ports
from modules.banner_grabber  import grab_banners
from modules.risk_analysis   import analyze_risks
from modules.report_generator import generate_reports


def main():
    """
    Main function that runs the entire security scan workflow.
    Each step is clearly labeled and results are passed to next step.
    """

    # Record start time to measure total scan duration
    start_time = time.time()

    print()
    print("=" * 60)
    print("  Starting scan at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)

    # ─────────────────────────────────────────────────────
    # STEP 1: Get Target Input
    # ─────────────────────────────────────────────────────
    target = get_target()


    # ─────────────────────────────────────────────────────
    # STEP 2: Resolve IP Address
    # ─────────────────────────────────────────────────────
    ip_data = resolve_ip(target)

    # Extract resolved IP for use in other modules
    ip_address = ip_data.get("ip_address")


    # ─────────────────────────────────────────────────────
    # STEP 3: DNS Lookup
    # ─────────────────────────────────────────────────────
    dns_data = get_dns_records(target)


    # ─────────────────────────────────────────────────────
    # STEP 4: WHOIS Lookup
    # ─────────────────────────────────────────────────────
    whois_data = get_whois_info(target)


    # ─────────────────────────────────────────────────────
    # STEP 5: Port Scanning
    # ─────────────────────────────────────────────────────
    port_results = scan_ports(target, ip_address)


    # ─────────────────────────────────────────────────────
    # STEP 6: Banner Grabbing
    # ─────────────────────────────────────────────────────
    banner_results = grab_banners(target, port_results, ip_address)


    # ─────────────────────────────────────────────────────
    # STEP 7: Risk Analysis
    # ─────────────────────────────────────────────────────
    risk_findings, risk_summary = analyze_risks(port_results)


    # ─────────────────────────────────────────────────────
    # STEP 8: Generate Reports
    # ─────────────────────────────────────────────────────
    report_files = generate_reports(
        target       = target,
        ip_data      = ip_data,
        dns_data     = dns_data,
        whois_data   = whois_data,
        port_results = port_results,
        banner_results = banner_results,
        risk_findings  = risk_findings,
        risk_summary   = risk_summary
    )

    # ─────────────────────────────────────────────────────
    # STEP 9: Final Summary
    # ─────────────────────────────────────────────────────
    end_time = time.time()
    duration = round(end_time - start_time, 2)

    print("\n" + "=" * 60)
    print("              SCAN COMPLETE - FINAL SUMMARY")
    print("=" * 60)
    print(f"  Target Scanned : {target}")
    print(f"  IP Address     : {ip_address or 'Not Resolved'}")
    print(f"  Scan Duration  : {duration} seconds")
    print()

    # Open ports summary
    open_ports = [p for p in port_results if p["status"] == "Open"]
    print(f"  Open Ports     : {len(open_ports)} found")
    for p in open_ports:
        print(f"    --> Port {p['port']} ({p['service']})")

    # Risk summary
    print()
    print(f"  Risk Findings  :")
    print(f"    CRITICAL : {risk_summary.get('CRITICAL', 0)}")
    print(f"    HIGH     : {risk_summary.get('HIGH', 0)}")
    print(f"    MEDIUM   : {risk_summary.get('MEDIUM', 0)}")
    print(f"    LOW      : {risk_summary.get('LOW', 0)}")

    # Report file locations
    print()
    print("  Reports Saved  :")
    print(f"    [TXT]  {report_files['txt']}")
    print(f"    [CSV]  {report_files['csv']}")
    print(f"    [JSON] {report_files['json']}")
    print()
    print("=" * 60)
    print("  Thank you for using the Security Reporting Tool!")
    print("  [DISCLAIMER]: Use only on authorized systems.")
    print("=" * 60)
    print()


# ── Program Entry Point ───────────────────────────────────
# This runs when you execute: python main.py
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\n\n[!] Scan interrupted by user (Ctrl+C). Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error occurred: {e}")
        print("[!] Please check your internet connection and try again.")
        sys.exit(1)
