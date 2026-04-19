# ============================================================
#  AKIN CHECK: Open Telnet Port Exposure
#  Target: telnet.0x10.cloud
#  Author: Akin Eludoyin
# ============================================================
#  This script checks whether Telnet is publicly exposed on
#  port 2323. Telnet is insecure because it transmits data
#  such as usernames and passwords in cleartext.
# ============================================================

import socket


def check_telnet_port() -> None:
    # Configure the target host and Telnet port
    target = "telnet.0x10.cloud"
    port = 2323

    print("=" * 50)
    print("  Akin's Telnet Exposure Check")
    print("=" * 50)
    print(f"\n  Target: {target}")
    print(f"  Port:   {port}")
    print("  Scanning...\n")

    # Create a TCP socket and set a timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)

    try:
        # Attempt connection to test whether the port is open
        result = sock.connect_ex((target, port))

        if result == 0:
            print("  [!] VULNERABILITY FOUND")
            print(f"  Port {port} (Telnet) is OPEN on {target}")
            print("  Security Risk: Telnet sends usernames, passwords, and commands in cleartext.")
            print("  This means an attacker monitoring traffic may be able to intercept credentials.")
        else:
            print("  [OK] Port is closed or not reachable")
            print(f"  Port {port} is not open on {target}")

    # Handle common network errors gracefully
    except socket.gaierror:
        print("  [ERROR] Could not resolve the target hostname.")
    except socket.timeout:
        print("  [ERROR] Connection attempt timed out.")
    except OSError as error:
        print(f"  [ERROR] Network error: {error}")
    finally:
        sock.close()


# Run the script
if __name__ == "__main__":
    check_telnet_port()