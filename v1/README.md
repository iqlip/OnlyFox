# OnlyFox

A Python utility for extracting saved passwords from Mozilla Firefox profiles on Windows systems. Designed for authorized security assessments and security research.

---

## Overview

OnlyFox extracts credentials stored by Firefox using the browser's native NSS (Network Security Services) library via Python's `ctypes` module. It requires no external Python packages — only the Python standard library and a Firefox installation.

| Capability | Source | Method |
|-----------|--------|--------|
| Password extraction | `logins.json` | NSS `PK11SDR_Decrypt` via `nss3.dll` |


## Files

| File | Description |
|------|-------------|
| `OnlyFox.py` | Main extraction script |

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


## Usage

### Default output (human-readable)
```bash
python OnlyFox.py
```

### JSON output
```bash
python OnlyFox.py --json
```


## Output Format

### Human-readable (default)
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
### JSON
```json
[
  {
    "browser": "Firefox",
    "profile": "default",
    "url": "https://example.com",
    "username": "alice",
    "password": "SuperSecret123"
  },
  {
    "browser": "Firefox",
    "profile": "work",
    "url": "https://github.com",
    "username": "alice@example.com",
    "password": "GitHubP@ssw0rd"
  }
]
```


## How It Works

1. **Profile discovery**: Reads `%APPDATA%\Mozilla\Firefox\profiles.ini` to locate Firefox profiles containing `logins.json`.
2. **NSS initialization**: Loads `nss3.dll` from the Firefox installation directory and initializes the NSS crypto context with `NSS_Init("sql:<profile_path>")`.
3. **Master password check**: Calls `PK11_CheckUserPassword` with an empty password. If a master password is set, the profile is skipped.
4. **Decryption**: For each entry in `logins.json`, base64-decodes the `encryptedUsername` and `encryptedPassword` fields, then calls `PK11SDR_Decrypt` to recover the plaintext.
5. **Cleanup**: Calls `NSS_Shutdown` to release NSS resources.

---

## Limitations

- **Passwords only**: This version extracts only saved passwords. Cookies, session data, and other browser artifacts are not retrieved.
- **Master password**: Profiles with a master password set are skipped. The script does not attempt to brute-force or bypass the master password.
- **Platform**: Windows only. The script relies on `nss3.dll`, which is part of the Windows Firefox distribution. Linux and macOS use different NSS library paths.
- **Firefox required**: The script cannot function without a Firefox installation, as it depends on Mozilla's NSS library (`nss3.dll`, `mozglue.dll`, and MSVC runtime).


## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Use OnlyFox only in environments you own or have explicit written permission to test. The author disclaims all liability for misuse or unauthorized use of this software..

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-21 | Initial release — Firefox password extraction via NSS ctypes |


