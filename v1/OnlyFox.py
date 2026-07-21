#!/usr/bin/env python3

"""
OnlyFox - Firefox Profile Audit Utility

Author       : Iqlip (@iqlip)
Organization : Currently Accepting Paychecks™
Employment   : Need Job :)
License      : MIT
Version      : 1.0.0

"Works on my machine."
"""

import ctypes
import ctypes.wintypes
import json
import os
import sys
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


# =============================================================================
# NSS DECODER
# =============================================================================

class NSSDecoder:
    """Wrapper for Firefox NSS library decryption."""

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
        """Locate and load nss3.dll."""
        sys64 = sys.maxsize > 2**32

        if sys64:
            locations = [
                r"C:\Program Files\Mozilla Firefox",
                r"C:\Program Files\Mozilla Thunderbird",
                r"C:\Program Files\Nightly",
                r"C:\Program Files\Firefox Nightly",
                r"C:\Program Files\Firefox Developer Edition",
            ]
        else:
            locations = [
                r"C:\Program Files (x86)\Mozilla Firefox",
                r"C:\Program Files (x86)\Mozilla Thunderbird",
                r"C:\Program Files (x86)\Nightly",
                r"C:\Program Files\Mozilla Firefox",
                r"C:\Program Files\Mozilla Thunderbird",
            ]

        locations.insert(0, "")

        for loc in locations:
            nsslib = os.path.join(loc, "nss3.dll")
            if not os.path.exists(nsslib):
                continue

            try:
                if loc:
                    os.environ["PATH"] = loc + ";" + os.environ.get("PATH", "")

                self.nss = ctypes.CDLL(nsslib)
                return
            except OSError:
                continue

        raise RuntimeError("Could not find nss3.dll. Make sure Firefox is installed.")

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
    """Find Firefox profile directories from profiles.ini."""
    profiles = []

    firefox_path = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox"
    profiles_ini = firefox_path / "profiles.ini"

    if not profiles_ini.exists():
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
                if (profile_path / "logins.json").exists():
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
        if (profile_path / "logins.json").exists():
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
# MAIN
# =============================================================================

def main():
    json_out = "-json" in sys.argv or "--json" in sys.argv

    all_entries = []

    try:
        firefox_profiles = find_firefox_profiles()
        for fp in firefox_profiles:
            try:
                entries = extract_firefox_passwords(fp["path"], fp["name"])
                all_entries.extend(entries)
            except Exception as e:
                if not json_out:
                    print(f"[!] Firefox\\{fp['name']} — extract failed: {e}", file=sys.stderr)
    except Exception as e:
        if not json_out:
            print(f"[!] Firefox — profile discovery failed: {e}", file=sys.stderr)

    if json_out:
        output = [e.to_dict() for e in all_entries]
        print(json.dumps(output, indent=2))
        return

    if not all_entries:
        print("[*] No saved Firefox passwords found.")
        return

    print(f"[+] Dumped {len(all_entries)} saved Firefox passwords:")
    print()
    for e in all_entries:
        print(f"  Browser : {e.browser} ({e.profile})")
        print(f"  URL     : {e.url}")
        print(f"  User    : {e.username}")
        print(f"  Pass    : {e.password}")
        print()


if __name__ == "__main__":
    main()
