#!/usr/bin/env python3

"""
OnlyFox - Firefox Profile Audit Utility

Author       : Iqlip (@iqlip)
Organization : Currently Accepting Paychecks™
Employment   : Need Job :)
License      : MIT

"Works on my machine."
"""

import ctypes
import ctypes.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from base64 import b64decode
from pathlib import Path


# =============================================================================
# NSS STRUCTS
# =============================================================================

class SECItem(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("data", ctypes.c_char_p),
        ("len", ctypes.c_uint),
    ]


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class LoginEntry:
    def __init__(self, browser, profile, url, username, password):
        self.browser = browser
        self.profile = profile
        self.url = url
        self.username = username
        self.password = password

    def to_dict(self):
        return {
            "browser": self.browser,
            "profile": self.profile,
            "url": self.url,
            "username": self.username,
            "password": self.password,
        }


class CookieEntry:
    def __init__(self, browser, profile, host, name, value, path, expiry, secure, httponly):
        self.browser = browser
        self.profile = profile
        self.host = host
        self.name = name
        self.value = value
        self.path = path
        self.expiry = expiry
        self.secure = secure
        self.httponly = httponly

    def to_dict(self):
        return {
            "browser": self.browser,
            "profile": self.profile,
            "host": self.host,
            "name": self.name,
            "value": self.value,
            "path": self.path,
            "expiry": self.expiry,
            "secure": self.secure,
            "httponly": self.httponly,
        }


# =============================================================================
# NSS DECODER
# =============================================================================

class NSSDecoder:
    """Wrapper for Firefox NSS library decryption on Linux."""

    def __init__(self):
        self.nss = None
        self._load_nss()

        self._NSS_Init = self.nss.NSS_Init
        self._NSS_Init.restype = ctypes.c_int
        self._NSS_Init.argtypes = [ctypes.c_char_p]

        self._NSS_Shutdown = self.nss.NSS_Shutdown
        self._NSS_Shutdown.restype = ctypes.c_int
        self._NSS_Shutdown.argtypes = []

        self._PK11_GetInternalKeySlot = self.nss.PK11_GetInternalKeySlot
        self._PK11_GetInternalKeySlot.restype = ctypes.c_void_p
        self._PK11_GetInternalKeySlot.argtypes = []

        self._PK11_FreeSlot = self.nss.PK11_FreeSlot
        self._PK11_FreeSlot.restype = None
        self._PK11_FreeSlot.argtypes = [ctypes.c_void_p]

        self._PK11_CheckUserPassword = self.nss.PK11_CheckUserPassword
        self._PK11_CheckUserPassword.restype = ctypes.c_int
        self._PK11_CheckUserPassword.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        self._PK11SDR_Decrypt = self.nss.PK11SDR_Decrypt
        self._PK11SDR_Decrypt.restype = ctypes.c_int
        self._PK11SDR_Decrypt.argtypes = [ctypes.POINTER(SECItem), ctypes.POINTER(SECItem), ctypes.c_void_p]

        self._SECITEM_ZfreeItem = self.nss.SECITEM_ZfreeItem
        self._SECITEM_ZfreeItem.restype = None
        self._SECITEM_ZfreeItem.argtypes = [ctypes.POINTER(SECItem), ctypes.c_int]

        self._PORT_GetError = self.nss.PORT_GetError
        self._PORT_GetError.restype = ctypes.c_int
        self._PORT_GetError.argtypes = []

        self._PR_ErrorToName = self.nss.PR_ErrorToName
        self._PR_ErrorToName.restype = ctypes.c_char_p
        self._PR_ErrorToName.argtypes = [ctypes.c_int]

        self._PR_ErrorToString = self.nss.PR_ErrorToString
        self._PR_ErrorToString.restype = ctypes.c_char_p
        self._PR_ErrorToString.argtypes = [ctypes.c_int, ctypes.c_uint32]

    def _load_nss(self):
        """Locate and load libnss3.so on Linux."""

        # Possible library names and paths
        lib_names = [
            "nss3",
            "libnss3.so",
            "libnss3.so.1",
        ]

        # Search paths
        search_paths = [
            # Standard system paths
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
            "/usr/lib",
            "/lib/x86_64-linux-gnu",
            "/lib64",
            "/lib",
            # Firefox-specific paths
            "/usr/lib/firefox",
            "/usr/lib64/firefox",
            "/usr/lib/x86_64-linux-gnu/firefox",
            "/opt/firefox",
            "/opt/firefox-esr",
            # Snap/Flatpak paths
            "/snap/firefox/current/usr/lib/firefox",
            "/var/lib/flatpak/app/org.mozilla.firefox/current/active/files/lib",
            # User-local installs
            str(Path.home() / ".local/lib"),
            str(Path.home() / ".local/lib/firefox"),
        ]

        # Try ctypes.util.find_library first
        for lib_name in lib_names:
            found = ctypes.util.find_library(lib_name)
            if found:
                try:
                    self.nss = ctypes.CDLL(found)
                    return
                except OSError:
                    pass

        # Try explicit paths
        for path in search_paths:
            for lib_name in lib_names:
                lib_path = os.path.join(path, lib_name)
                if os.path.exists(lib_path):
                    try:
                        self.nss = ctypes.CDLL(lib_path)
                        return
                    except OSError:
                        pass

        raise RuntimeError(
            "Could not find libnss3.so. "
            "Make sure Firefox is installed or libnss3 is available. "
            "Try: sudo apt install libnss3"
        )

    def decode(self, data64):
        """Decrypt base64-encoded NSS encrypted data."""
        data = b64decode(data64)

        inp = SECItem()
        inp.type = 0
        inp.data = ctypes.cast(ctypes.create_string_buffer(data), ctypes.c_char_p)
        inp.len = len(data)

        out = SECItem()
        out.type = 0
        out.data = None
        out.len = 0

        e = self._PK11SDR_Decrypt(ctypes.byref(inp), ctypes.byref(out), None)

        try:
            if e == -1:
                err = self._PORT_GetError()
                name = self._PR_ErrorToName(err)
                name = "NULL" if name is None else name.decode("utf-8", errors="replace")
                text = self._PR_ErrorToString(err, 0)
                text = text.decode("utf-8", errors="replace") if text else ""
                raise RuntimeError(f"NSS decryption failed: {name} - {text}")

            res = ctypes.string_at(out.data, out.len).decode("utf-8", errors="replace")
        finally:
            self._SECITEM_ZfreeItem(ctypes.byref(out), 0)

        return res


# =============================================================================
# PROFILE DISCOVERY
# =============================================================================

def find_firefox_profiles():
    """Find Firefox profile directories from profiles.ini on Linux."""
    profiles = []

    firefox_path = Path.home() / ".mozilla" / "firefox"
    profiles_ini = firefox_path / "profiles.ini"

    if not profiles_ini.exists():
        # Try snap/flatpak paths
        snap_path = Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox"
        if (snap_path / "profiles.ini").exists():
            firefox_path = snap_path
            profiles_ini = snap_path / "profiles.ini"
        else:
            flatpak_path = Path.home() / ".var" / "app" / "org.mozilla.firefox" / "data" / "mozilla" / "firefox"
            if (flatpak_path / "profiles.ini").exists():
                firefox_path = flatpak_path
                profiles_ini = flatpak_path / "profiles.ini"
            else:
                return profiles

    with open(profiles_ini, "r", encoding="utf-8") as f:
        content = f.read()

    current_section = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        if line.startswith("[") and line.endswith("]"):
            if current_section and "Path" in current_section:
                profile_path = firefox_path / current_section["Path"]
                has_logins = (profile_path / "logins.json").exists()
                has_cookies = (profile_path / "cookies.sqlite").exists()
                if has_logins or has_cookies:
                    profiles.append({
                        "name": current_section.get("Name", "default"),
                        "path": str(profile_path),
                    })
            current_section = {}
        elif "=" in line:
            key, value = line.split("=", 1)
            current_section[key.strip()] = value.strip()

    # Last section
    if current_section and "Path" in current_section:
        profile_path = firefox_path / current_section["Path"]
        has_logins = (profile_path / "logins.json").exists()
        has_cookies = (profile_path / "cookies.sqlite").exists()
        if has_logins or has_cookies:
            profiles.append({
                "name": current_section.get("Name", "default"),
                "path": str(profile_path),
            })

    return profiles


# =============================================================================
# PASSWORD EXTRACTION
# =============================================================================

def extract_firefox_passwords(profile_path, profile_name):
    """Extract passwords from Firefox logins.json using NSS."""
    entries = []

    logins_path = Path(profile_path) / "logins.json"
    if not logins_path.exists():
        return entries

    with open(logins_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    logins = data.get("logins", [])
    if not logins:
        return entries

    nss = NSSDecoder()

    profile_encoded = ("sql:" + profile_path).encode("utf-8")
    e = nss._NSS_Init(profile_encoded)
    if e != 0:
        raise RuntimeError(f"NSS_Init failed for profile: {profile_path}")

    try:
        keyslot = nss._PK11_GetInternalKeySlot()
        if not keyslot:
            raise RuntimeError("Failed to get internal key slot")

        try:
            pw_check = nss._PK11_CheckUserPassword(keyslot, b"")
            if pw_check != 0:
                return entries  # Master password required
        finally:
            nss._PK11_FreeSlot(keyslot)

        for login in logins:
            try:
                url = login.get("hostname", "")
                username = nss.decode(login.get("encryptedUsername", ""))
                password = nss.decode(login.get("encryptedPassword", ""))

                if username or password:
                    entries.append(LoginEntry("Firefox", profile_name, url, username, password))
            except Exception:
                continue
    finally:
        nss._NSS_Shutdown()

    return entries


# =============================================================================
# COOKIE EXTRACTION
# =============================================================================

def extract_firefox_cookies(profile_path, profile_name):
    """Extract cookies from Firefox cookies.sqlite (plaintext, no NSS needed)."""
    entries = []

    cookies_db = Path(profile_path) / "cookies.sqlite"
    if not cookies_db.exists():
        return entries

    # Copy to temp to avoid lock
    with tempfile.NamedTemporaryFile(suffix="-firefox-cookies.sqlite", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        shutil.copy2(str(cookies_db), tmp_path)

        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies"
        )

        for row in cursor.fetchall():
            host, name, value, path, expiry, is_secure, is_httponly = row
            entries.append(CookieEntry(
                "Firefox",
                profile_name,
                host,
                name,
                value,
                path,
                expiry,
                bool(is_secure),
                bool(is_httponly)
            ))

        conn.close()
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    return entries


# =============================================================================
# MAIN
# =============================================================================

def main():
    json_out = "-json" in sys.argv or "--json" in sys.argv
    cookies_only = "-cookies" in sys.argv or "--cookies" in sys.argv
    passwords_only = "-passwords" in sys.argv or "--passwords" in sys.argv

    all_passwords = []
    all_cookies = []

    try:
        firefox_profiles = find_firefox_profiles()
        for fp in firefox_profiles:
            try:
                if not cookies_only:
                    passwords = extract_firefox_passwords(fp["path"], fp["name"])
                    all_passwords.extend(passwords)
            except Exception as e:
                if not json_out:
                    print(f"[!] Firefox/{fp['name']} — password extract failed: {e}", file=sys.stderr)

            try:
                if not passwords_only:
                    cookies = extract_firefox_cookies(fp["path"], fp["name"])
                    all_cookies.extend(cookies)
            except Exception as e:
                if not json_out:
                    print(f"[!] Firefox/{fp['name']} — cookie extract failed: {e}", file=sys.stderr)
    except Exception as e:
        if not json_out:
            print(f"[!] Firefox — profile discovery failed: {e}", file=sys.stderr)

    # --- OUTPUT ---
    if json_out:
        output = {
            "passwords": [e.to_dict() for e in all_passwords],
            "cookies": [e.to_dict() for e in all_cookies],
        }
        print(json.dumps(output, indent=2))
        return

    # Passwords output
    if not cookies_only:
        if not all_passwords:
            print("[*] No saved Firefox passwords found.")
        else:
            print(f"\n[+] Dumped {len(all_passwords)} saved Firefox passwords:\n")
            for e in all_passwords:
                print(f"  Browser : {e.browser} ({e.profile})")
                print(f"  URL     : {e.url}")
                print(f"  User    : {e.username}")
                print(f"  Pass    : {e.password}\n")

    # Cookies output
    if not passwords_only:
        if not all_cookies:
            print("[*] No Firefox cookies found.")
        else:
            print(f"\n[+] Dumped {len(all_cookies)} Firefox cookies:\n")
            for e in all_cookies:
                secure_flag = " [Secure]" if e.secure else ""
                http_flag = " [HttpOnly]" if e.httponly else ""
                print(f"  Browser : {e.browser} ({e.profile})")
                print(f"  Host    : {e.host}")
                print(f"  Name    : {e.name}")
                print(f"  Value   : {e.value}")
                print(f"  Path    : {e.path}")
                print(f"  Expiry  : {e.expiry}{secure_flag}{http_flag}\n")


if __name__ == "__main__":
    main()
