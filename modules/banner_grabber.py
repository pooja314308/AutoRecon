# ============================================================
# MODULE: banner_grabber.py
# PURPOSE: Attempts to grab service banners from open ports.
#          Banners reveal software name and version information.
# ============================================================

import socket   # For network connections


def grab_banners(target, port_results, ip_address=None):
    """
    Loops through open ports and tries to grab the banner
    (service identification string) from each one.

    A banner is like a "hello" message from the service.
    Example: "SSH-2.0-OpenSSH_7.4" tells us SSH version.

    Returns a list of dictionaries with banner information.
    """

    print("\n[*] MODULE 5: BANNER GRABBING")
    print("-" * 40)
    print("[*] Attempting to grab service banners from open ports...")
    print()

    # Target to connect to
    scan_target = ip_address if ip_address else target

    banner_results = []  # Store all banner results

    # Filter only open ports for banner grabbing
    open_ports = [p for p in port_results if p["status"] == "Open"]

    if not open_ports:
        print("[-] No open ports found. Skipping banner grabbing.")
        return banner_results

    for port_info in open_ports:
        port = port_info["port"]
        service = port_info["service"]

        banner_data = {
            "port": port,
            "service": service,
            "banner": None,
            "status": "No Banner"
        }

        try:
            # Create socket and set timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            # Connect to the open port
            sock.connect((scan_target, port))

            # For HTTP port, send a proper HTTP request to get response
            if port == 80:
                # Send HTTP GET request
                http_request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                sock.send(http_request.encode())

            elif port == 443:
                # HTTPS is encrypted, basic socket won't get banner easily
                banner_data["banner"] = "HTTPS (SSL/TLS Encrypted - Banner requires SSL handshake)"
                banner_data["status"] = "Detected"
                sock.close()
                print(f"[+] Port {port} ({service}): HTTPS Detected (Encrypted)")
                banner_results.append(banner_data)
                continue

            else:
                # For other ports, just send a blank line or newline
                # Many services send banner automatically on connect
                sock.send(b"\r\n")

            # Try to receive banner data (up to 1024 bytes)
            raw_banner = sock.recv(1024)

            # Decode bytes to string, ignore non-printable characters
            banner = raw_banner.decode("utf-8", errors="ignore").strip()

            if banner:
                # Clean up the banner (remove extra newlines/spaces)
                banner = " | ".join(banner.splitlines())
                banner_data["banner"] = banner
                banner_data["status"] = "Grabbed"
                print(f"[+] Port {port} ({service}):")
                print(f"    Banner: {banner[:100]}")  # Show first 100 chars
            else:
                banner_data["status"] = "Empty Banner"
                print(f"[-] Port {port} ({service}): Connected but no banner returned")

            sock.close()

        except socket.timeout:
            banner_data["status"] = "Timeout"
            print(f"[?] Port {port} ({service}): Connection timed out")

        except ConnectionRefusedError:
            banner_data["status"] = "Refused"
            print(f"[-] Port {port} ({service}): Connection refused")

        except Exception as e:
            banner_data["status"] = f"Error: {str(e)[:30]}"
            print(f"[!] Port {port} ({service}): {e}")

        banner_results.append(banner_data)

    return banner_results
