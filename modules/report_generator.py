# ============================================================
# MODULE: report_generator.py
# PURPOSE: Generates final security reports in TXT, CSV, and
#          JSON formats from all collected scan data
# ============================================================

import json        # For JSON report
import csv         # For CSV report
import os          # For file/folder operations
from datetime import datetime  # For timestamps


def generate_reports(target, ip_data, dns_data, whois_data,
                     port_results, banner_results, risk_findings, risk_summary):
    """
    Takes all collected data and generates three report files:
    1. report.txt  - Human-readable text report
    2. report.csv  - Spreadsheet-compatible CSV
    3. report.json - Machine-readable JSON format

    All reports are saved in the 'reports/' folder.
    Returns the file paths of all generated reports.
    """

    print("\n[*] MODULE 7: REPORT GENERATOR")
    print("-" * 40)

    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")

    # File paths
    txt_file  = os.path.join(reports_dir, f"report_{safe_target}_{timestamp}.txt")
    csv_file  = os.path.join(reports_dir, f"report_{safe_target}_{timestamp}.csv")
    json_file = os.path.join(reports_dir, f"report_{safe_target}_{timestamp}.json")

    # Generate all reports
    _generate_txt_report(txt_file, target, ip_data, dns_data, whois_data,
                         port_results, banner_results, risk_findings, risk_summary)

    _generate_csv_report(csv_file, target, port_results, risk_findings)

    _generate_json_report(json_file, target, ip_data, dns_data, whois_data,
                          port_results, banner_results, risk_findings, risk_summary)

    # Print completion message
    print("\n[+] Reports Generated Successfully:")
    print(f"    [TXT]  {txt_file}")
    print(f"    [CSV]  {csv_file}")
    print(f"    [JSON] {json_file}")

    return {
        "txt": txt_file,
        "csv": csv_file,
        "json": json_file
    }


# ─────────────────────────────────────────────────────────────
# INTERNAL FUNCTION: Generate TXT Report
# ─────────────────────────────────────────────────────────────
def _generate_txt_report(filepath, target, ip_data, dns_data, whois_data,
                          port_results, banner_results, risk_findings, risk_summary):
    """Creates a human-readable text security report."""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(filepath, "w") as f:

        # ── HEADER ──────────────────────────────────────────
        f.write("=" * 65 + "\n")
        f.write("      AUTOMATED INFORMATION GATHERING & SECURITY REPORT\n")
        f.write("           Diploma Final Year Project - Cyber Security\n")
        f.write("=" * 65 + "\n\n")

        f.write(f"  Target     : {target}\n")
        f.write(f"  Scan Date  : {now}\n")
        f.write(f"  Report By  : Automated Security Tool v1.0\n")
        f.write("\n" + "=" * 65 + "\n\n")

        # ── SECTION 1: IP RESOLUTION ────────────────────────
        f.write("SECTION 1: IP RESOLUTION\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Target       : {ip_data.get('target', 'N/A')}\n")
        f.write(f"  IP Address   : {ip_data.get('ip_address', 'Not Resolved')}\n")
        f.write(f"  Status       : {ip_data.get('status', 'N/A')}\n")
        if ip_data.get("error"):
            f.write(f"  Error        : {ip_data['error']}\n")
        f.write("\n")

        # ── SECTION 2: DNS RECORDS ──────────────────────────
        f.write("SECTION 2: DNS RECORDS\n")
        f.write("-" * 40 + "\n")
        for rtype in ["A", "MX", "NS", "TXT"]:
            records = dns_data.get(rtype, [])
            if records:
                f.write(f"  {rtype} Records:\n")
                for rec in records:
                    f.write(f"    --> {rec}\n")
            else:
                f.write(f"  {rtype} Records: Not Found\n")
        f.write("\n")

        # ── SECTION 3: WHOIS INFORMATION ────────────────────
        f.write("SECTION 3: WHOIS INFORMATION\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Domain Name  : {whois_data.get('domain_name', 'N/A')}\n")
        f.write(f"  Registrar    : {whois_data.get('registrar', 'N/A')}\n")
        f.write(f"  Created On   : {whois_data.get('creation_date', 'N/A')}\n")
        f.write(f"  Expires On   : {whois_data.get('expiration_date', 'N/A')}\n")
        f.write(f"  Last Updated : {whois_data.get('updated_date', 'N/A')}\n")
        f.write(f"  Country      : {whois_data.get('country', 'N/A')}\n")
        f.write(f"  Contact Email: {whois_data.get('emails', 'N/A')}\n")
        name_servers = whois_data.get("name_servers", [])
        if name_servers:
            f.write("  Name Servers :\n")
            for ns in name_servers:
                f.write(f"    --> {ns}\n")
        f.write("\n")

        # ── SECTION 4: PORT SCAN RESULTS ────────────────────
        f.write("SECTION 4: PORT SCAN RESULTS\n")
        f.write("-" * 40 + "\n")
        f.write(f"  {'PORT':<8} {'STATUS':<10} {'SERVICE'}\n")
        f.write(f"  {'-'*6:<8} {'-'*8:<10} {'-'*30}\n")
        for p in port_results:
            f.write(f"  {p['port']:<8} {p['status']:<10} {p['service']}\n")
        open_count = sum(1 for p in port_results if p["status"] == "Open")
        f.write(f"\n  Total Open Ports: {open_count} / {len(port_results)}\n\n")

        # ── SECTION 5: BANNER GRABBING ──────────────────────
        f.write("SECTION 5: BANNER GRABBING\n")
        f.write("-" * 40 + "\n")
        if banner_results:
            for b in banner_results:
                f.write(f"  Port {b['port']} ({b['service']}):\n")
                f.write(f"    Status : {b['status']}\n")
                if b.get("banner"):
                    # Wrap long banners
                    banner_text = str(b["banner"])[:200]
                    f.write(f"    Banner : {banner_text}\n")
                f.write("\n")
        else:
            f.write("  No banners captured.\n\n")

        # ── SECTION 6: RISK ANALYSIS ────────────────────────
        f.write("SECTION 6: SECURITY RISK ANALYSIS\n")
        f.write("-" * 40 + "\n")

        f.write("  Risk Summary:\n")
        f.write(f"    CRITICAL : {risk_summary.get('CRITICAL', 0)}\n")
        f.write(f"    HIGH     : {risk_summary.get('HIGH', 0)}\n")
        f.write(f"    MEDIUM   : {risk_summary.get('MEDIUM', 0)}\n")
        f.write(f"    LOW      : {risk_summary.get('LOW', 0)}\n")
        f.write(f"    INFO     : {risk_summary.get('INFO', 0)}\n\n")

        if risk_findings:
            f.write("  Detailed Findings:\n\n")
            for idx, risk in enumerate(risk_findings, 1):
                f.write(f"  [{idx}] Port {risk['port']} - {risk['risk']}\n")
                f.write(f"      Severity    : {risk['level']}\n")
                f.write(f"      Service     : {risk['service']}\n")
                f.write(f"      Description : {risk['description']}\n")
                f.write(f"      Fix         : {risk['recommendation']}\n\n")
        else:
            f.write("  No significant risks identified from open ports.\n\n")

        # ── FOOTER ──────────────────────────────────────────
        f.write("=" * 65 + "\n")
        f.write("  DISCLAIMER: This scan is for authorized educational use only.\n")
        f.write("  Unauthorized scanning of systems is illegal and unethical.\n")
        f.write("=" * 65 + "\n")
        f.write(f"  Report generated at: {now}\n")
        f.write("=" * 65 + "\n")

    print(f"[+] TXT Report saved: {filepath}")


# ─────────────────────────────────────────────────────────────
# INTERNAL FUNCTION: Generate CSV Report
# ─────────────────────────────────────────────────────────────
def _generate_csv_report(filepath, target, port_results, risk_findings):
    """Creates a CSV report of port scan and risk findings."""

    with open(filepath, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Port scan table
        writer.writerow(["PORT SCAN RESULTS"])
        writer.writerow(["Target", "Port", "Status", "Service"])
        for p in port_results:
            writer.writerow([target, p["port"], p["status"], p["service"]])

        writer.writerow([])  # Blank row separator

        # Risk analysis table
        writer.writerow(["RISK ANALYSIS RESULTS"])
        writer.writerow(["Port", "Risk Level", "Risk Name", "Service", "Description", "Recommendation"])
        for risk in risk_findings:
            writer.writerow([
                risk["port"],
                risk["level"],
                risk["risk"],
                risk["service"],
                risk["description"][:100],  # Truncate for CSV readability
                risk["recommendation"][:100]
            ])

    print(f"[+] CSV Report saved: {filepath}")


# ─────────────────────────────────────────────────────────────
# INTERNAL FUNCTION: Generate JSON Report
# ─────────────────────────────────────────────────────────────
def _generate_json_report(filepath, target, ip_data, dns_data, whois_data,
                           port_results, banner_results, risk_findings, risk_summary):
    """Creates a complete JSON report with all scan data."""

    report = {
        "report_metadata": {
            "tool": "Automated Information Gathering & Security Report Tool",
            "version": "1.0",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target
        },
        "ip_resolution": ip_data,
        "dns_records": dns_data,
        "whois_information": whois_data,
        "port_scan": port_results,
        "banner_grabbing": banner_results,
        "risk_analysis": {
            "summary": risk_summary,
            "findings": risk_findings
        }
    }

    with open(filepath, "w") as jf:
        json.dump(report, jf, indent=4, default=str)

    print(f"[+] JSON Report saved: {filepath}")
