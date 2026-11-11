import sys

try:
    import win32evtlog
except ImportError as e:
    print(f"[-] Critical Error: Could not import pywin32 modules: {e}")
    print("[-] Make sure you ran: python -m pip install pywin32")
    sys.exit(1)

# Dictionary of high-interest Security Event IDs and their meanings
SUSPICIOUS_EVENTS = {
    4625: "Failed Logon Attempt (Potential Brute Force)",
    4672: "Special Privileges Assigned to New Logon (Admin Escalation)",
    4720: "A User Account Was Created",
    4726: "A User Account Was Deleted",
    4648: "A Logon Was Attempted Using Explicit Credentials",
    4740: "A User Account Was Locked Out"
}

def parse_security_logs(max_records=200):
    server = 'localhost'
    log_type = 'Security'
    
    print(f"[*] Connecting to Windows '{log_type}' Event Log channel...")
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        print(f"[-] Error opening event log. Make sure you run this script as Administrator: {e}")
        return

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
    print(f"[+] Total records available in log: {total_records}")
    print(f"[*] Scanning the last {max_records} entries for security anomalies...\n")
    print(f"{'TIMESTAMP':<22} | {'EVENT ID':<8} | {'DESCRIPTION'}")
    print("-" * 75)

    scanned_count = 0
    alert_count = 0

    while scanned_count < max_records:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break

        for event in events:
            scanned_count += 1
            if scanned_count > max_records:
                break

            event_id = event.EventID & 0xFFFF  
            
            if event_id in SUSPICIOUS_EVENTS:
                alert_count += 1
                timestamp = str(event.TimeGenerated)
                description = SUSPICIOUS_EVENTS[event_id]
                print(f"{timestamp:<22} | {event_id:<8} | [!] {description}")

    print("-" * 75)
    print(f"[+] Scan complete. Scanned {scanned_count} events. Flagged {alert_count} security alerts.")
    win32evtlog.CloseEventLog(hand)

if __name__ == "__main__":
    parse_security_logs(max_records=200)
    input("\n[+] Press Enter to exit...")