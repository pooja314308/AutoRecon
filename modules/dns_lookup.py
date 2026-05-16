# ============================================================
# MODULE: dns_lookup.py
# PURPOSE: Fetches DNS records for the target domain.
#          Includes A, MX, NS, and TXT records.
# ============================================================

import dns.resolver  # Requires: pip install dnspython


def get_dns_records(target):
    """
    Queries DNS records for the given target domain.
    Returns a dictionary containing all found records.

    Record Types:
    - A     : Maps domain to IPv4 address
    - MX    : Mail Exchange server (for email)
    - NS    : Name Servers (who manages DNS)
    - TXT   : Text records (SPF, DKIM, verification codes)
    """

    print("\n[*] MODULE 2: DNS LOOKUP")
    print("-" * 40)

    # Store all results here
    dns_results = {
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "errors": {}
    }

    # List of record types to query
    record_types = ["A", "MX", "NS", "TXT"]

    for record_type in record_types:
        try:
            # Query DNS for this record type
            answers = dns.resolver.resolve(target, record_type)

            print(f"\n[+] {record_type} Records:")

            for rdata in answers:
                record_value = str(rdata)

                # For MX records, also show preference number
                if record_type == "MX":
                    record_value = f"{rdata.exchange} (Priority: {rdata.preference})"

                dns_results[record_type].append(record_value)
                print(f"    --> {record_value}")

        except dns.resolver.NoAnswer:
            # No records of this type found
            dns_results["errors"][record_type] = "No records found"
            print(f"\n[-] {record_type} Records: Not Found")

        except dns.resolver.NXDOMAIN:
            # Domain does not exist
            dns_results["errors"][record_type] = "Domain does not exist"
            print(f"\n[-] {record_type} Records: Domain does not exist")

        except Exception as e:
            # Any other error
            dns_results["errors"][record_type] = str(e)
            print(f"\n[-] {record_type} Records: Error - {e}")

    return dns_results
