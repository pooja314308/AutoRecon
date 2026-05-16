# ============================================================
# MODULE: whois_lookup.py
# PURPOSE: Collects WHOIS registration details for the domain
#          such as registrar, creation date, expiry, and owner
# ============================================================

import whois  # Requires: pip install python-whois


def get_whois_info(target):
    """
    Performs a WHOIS lookup on the target domain.
    Returns a dictionary with registration details.

    WHOIS gives us:
    - Who registered the domain
    - When it was registered
    - When it expires
    - Which registrar manages it
    - Name servers
    """

    print("\n[*] MODULE 3: WHOIS LOOKUP")
    print("-" * 40)

    # Store results
    whois_data = {
        "domain_name": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": None,
        "emails": None,
        "country": None,
        "raw": None,
        "error": None
    }

    try:
        # Perform the WHOIS query
        w = whois.whois(target)

        # Extract domain name
        whois_data["domain_name"] = str(w.domain_name) if w.domain_name else "N/A"

        # Extract registrar (company that registered the domain)
        whois_data["registrar"] = str(w.registrar) if w.registrar else "N/A"

        # Extract creation date (when domain was first registered)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                whois_data["creation_date"] = str(w.creation_date[0])
            else:
                whois_data["creation_date"] = str(w.creation_date)
        else:
            whois_data["creation_date"] = "N/A"

        # Extract expiration date (when domain expires)
        if w.expiration_date:
            if isinstance(w.expiration_date, list):
                whois_data["expiration_date"] = str(w.expiration_date[0])
            else:
                whois_data["expiration_date"] = str(w.expiration_date)
        else:
            whois_data["expiration_date"] = "N/A"

        # Extract last updated date
        if w.updated_date:
            if isinstance(w.updated_date, list):
                whois_data["updated_date"] = str(w.updated_date[0])
            else:
                whois_data["updated_date"] = str(w.updated_date)
        else:
            whois_data["updated_date"] = "N/A"

        # Extract name servers
        if w.name_servers:
            if isinstance(w.name_servers, list):
                whois_data["name_servers"] = [str(ns) for ns in w.name_servers]
            else:
                whois_data["name_servers"] = [str(w.name_servers)]

        # Extract status
        if w.status:
            if isinstance(w.status, list):
                whois_data["status"] = str(w.status[0])
            else:
                whois_data["status"] = str(w.status)

        # Extract emails
        if w.emails:
            whois_data["emails"] = str(w.emails)

        # Extract country
        if w.country:
            whois_data["country"] = str(w.country)

        # Print results nicely
        print(f"[+] Domain Name    : {whois_data['domain_name']}")
        print(f"[+] Registrar      : {whois_data['registrar']}")
        print(f"[+] Created On     : {whois_data['creation_date']}")
        print(f"[+] Expires On     : {whois_data['expiration_date']}")
        print(f"[+] Last Updated   : {whois_data['updated_date']}")
        print(f"[+] Country        : {whois_data['country']}")
        print(f"[+] Contact Email  : {whois_data['emails']}")

        if whois_data["name_servers"]:
            print(f"[+] Name Servers   :")
            for ns in whois_data["name_servers"]:
                print(f"    --> {ns}")

    except Exception as e:
        # WHOIS can fail due to rate limiting or private domains
        whois_data["error"] = str(e)
        print(f"[-] WHOIS lookup failed: {e}")
        print("[!] Note: Some domains hide WHOIS info (privacy protection)")

    return whois_data
