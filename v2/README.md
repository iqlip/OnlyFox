# OnlyFox

A Python utility for extracting saved passwords and cookies from Mozilla Firefox profiles on Windows systems. Designed for authorized security assessments and security research.

---

## Overview

OnlyFox extracts credentials stored by Firefox using the browser's native NSS (Network Security Services) library via Python's `ctypes` module. It requires no external Python packages — only the Python standard library and a Firefox installation.

| Capability | Source | Method |
|-----------|--------|--------|
| Password extraction | `logins.json` | NSS `PK11SDR_Decrypt` via `nss3.dll` |
| Cookie extraction | `cookies.sqlite` | Direct SQLite query |

---

## Files

| File | Description |
|------|-------------|
| `OnlyFox.py` | Main extraction script |

---

## Requirements

- **Python 3.8 or later**
- **Windows operating system** (relies on `nss3.dll`)
- **Firefox installed** (the script loads `nss3.dll` and its dependencies from the Firefox installation directory)

No additional Python packages are required. OnlyFox uses only the standard library.

---

## Installation

No installation is required. Download `OnlyFox.py` and run it with Python.

```bash
python OnlyFox.py
```

---

## Usage

### Default output (passwords + cookies, human-readable)
```bash
python OnlyFox.py
```

### JSON output
```bash
python OnlyFox.py --json
```

### Passwords only
```bash
python OnlyFox.py --passwords
```

### Cookies only
```bash
python OnlyFox.py --cookies
```

---

## Output Format

### Human-readable (default)

Passwords:
```
[+] Dumped 2 saved Firefox passwords:

  Browser : Firefox (default)
  URL     : https://example.com
  User    : alice
  Pass    : SuperSecret123

  Browser : Firefox (work)
  URL     : https://github.com
  User    : alice@example.com
  Pass    : GitHubP@ssw0rd
```

Cookies:
```
[+] Dumped 5 Firefox cookies:

  Browser : Firefox (default)
  Host    : .example.com
  Name    : session_id
  Value   : abc123xyz
  Path    : /
  Expiry  : 1753100000 [Secure] [HttpOnly]
```

### JSON

```json
{
  "passwords": [
    {
      "browser": "Firefox",
      "profile": "default",
      "url": "https://example.com",
      "username": "alice",
      "password": "SuperSecret123"
    }
  ],
  "cookies": [
    {
      "browser": "Firefox",
      "profile": "default",
      "host": ".example.com",
      "name": "session_id",
      "value": "abc123xyz",
      "path": "/",
      "expiry": 1753100000,
      "secure": true,
      "httponly": true
    }
  ]
}
```

---

## How It Works

### Password Extraction

1. **Profile discovery**: Reads `%APPDATA%\Mozilla\Firefox\profiles.ini` to locate Firefox profiles containing `logins.json` or `cookies.sqlite`.
2. **NSS initialization**: Loads `nss3.dll` from the Firefox installation directory and initializes the NSS crypto context with `NSS_Init("sql:<profile_path>")`.
3. **Master password check**: Calls `PK11_CheckUserPassword` with an empty password. If a master password is set, the profile is skipped.
4. **Decryption**: For each entry in `logins.json`, base64-decodes the `encryptedUsername` and `encryptedPassword` fields, then calls `PK11SDR_Decrypt` to recover the plaintext.
5. **Cleanup**: Calls `NSS_Shutdown` to release NSS resources.

### Cookie Extraction

1. **Database copy**: Copies `cookies.sqlite` to a temporary file to avoid locking the original database while Firefox is running.
2. **Query**: Opens the SQLite database and queries the `moz_cookies` table for `host`, `name`, `value`, `path`, `expiry`, `isSecure`, and `isHttpOnly`.
3. **Cleanup**: Deletes the temporary database copy.

---


## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Use OnlyFox only in environments you own or have explicit written permission to test. The author disclaims all liability for misuse or unauthorized use of this software.

