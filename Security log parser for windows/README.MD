# Windows Event Log Security Parser

A Python tool that reads and checks Windows Security Event Logs in real time. It looks for events related to login attempts and permission changes. This helps find signs of hacking or misuse of admin rights.

---

## Features

* **Works with Windows:** Uses the built-in Windows Event Log system through `pywin32`.

* **Focuses on security events:** It automatically spots activity like:

* **Event ID 4625:** Failed login attempt (could be a brute-force attack)

* **Event ID 4672:** privileges given (possible admin escalation)

* **Event ID 4648:** Login using known username and password ( credentials)

* **Event ID 4720 / 4726:** User account created or deleted

* **Event ID 4740:** Account locked out

* **Clean and easy to read output:** Shows events in a table with timestamps and descriptions.

---

## Requirements

* **Operating System:** Windows 10 Windows 11 or Windows Server

* **Python:** Version 3.x must be. Available in the system path

* **Permissions:** Must run from an Administrator Command Prompt to access the Security log

---

## Installation and Setup

1. **Get the code:**

```bash

git clone https://github.com/your-username/windows-security-log-parser.git

cd windows-security-log-parser

```

2. **Install needed packages:**

```bash

python -m pip install pywin32

```

---

## How to Use

Run the script from an **Administrator command prompt**:

```bash

python security_log_parser.py

```

### Sample Output

```text

[*] Connecting to Windows 'Security' Event Log channel...

[+] Total records available in log: 45210

[*] Scanning the 200 entries for security anomalies...

TIMESTAMP              | EVENT ID | DESCRIPTION

---------------------------------------------------------------------------

2026-11-10 14:59:25    | 4672     | [!] Special Privileges Assigned to New Logon (Admin Escalation)

2026-11-10 14:59:23    | 4625     | [!] Failed Logon Attempt (Potential Brute Force)

---------------------------------------------------------------------------

[+] Scan complete. Scanned 200 events. Flagged 2 security alerts.

```

---

## Testing the Tool

To try it out on your machine:

1. Lock your computer using `Windows Key + L`

2. Try logging in with a password a few times to trigger **Event ID 4625**

3. Unlock your computer. Run the script, from an Administrator terminal

4. Check if the failed login shows up in the results

---

## License

This project is released under the MIT License. You are free to use it modify it or include it in your projects.
