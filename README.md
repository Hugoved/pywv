# pywv

**pywv** is a Python-based tool for parsing, analyzing, and interacting with **Widevine (WVD) device files** and associated DRM structures. It provides low-level access to device data, cryptographic components, and license-related metadata, enabling precise inspection and controlled handling of Widevine workflows.

---

## Features

* Parsing and loading of **Widevine Device (WVD) files** 
* Support for **WVD version migration (v1 → v2)** 
* Extraction of **device attributes** (system ID, security level, client identification) 
* Decoding of **Widevine protobuf structures** (ClientIdentification, certificates, licenses) 
* Integration with **cryptographic primitives** (RSA, AES, CMAC, HMAC) 
* Parsing and manipulation of **PSSH (Widevine / PlayReady)** containers 
* License processing and **content key extraction** via CDM workflows 

---

## Requirements

* Python 3.9 or higher
* `pycryptodome`
* `construct`
* `protobuf`
* `pymp4`
* `requests`

Installation:

```bash
pip install pycryptodome construct protobuf pymp4 requests
```

---

## Usage

```bash
python pywv.py [options]
```
---

## Examples

### Basic Usage

```python
import requests
from pywv import PSSH, Device, Cdm

pssh = PSSH("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==")

device = Device.load("xiaomi_redmi_note_4x_15.0.0_e15a9e5f_8159_l3.wvd")
cdm = Cdm.from_device(device)
session_id = cdm.open()

try:
    challenge = cdm.get_license_challenge(session_id, pssh)

    license_response = requests.post(
        "https://cwip-shaka-proxy.appspot.com/no_auth",
        data=challenge,
    )
    license_response.raise_for_status()

    cdm.parse_license(session_id, license_response.content)

    for key in cdm.get_keys(session_id):
        print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")

finally:
    cdm.close(session_id)
```

---

### Using JSON Device Configuration

```python
# wv.json example:
# {
#   "security_level": 3,
#   "session_id_type": "android",
#   "private_key_available": true,
#   "vmp": false
# }

import json
import requests
from pathlib import Path
from pywv import PSSH, Device, Cdm

base_path = Path(__file__).resolve().parent

with open(base_path / "wv.json", "r", encoding="utf-8") as f:
    wv = json.load(f)

pssh = PSSH("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==")

if not wv.get("private_key_available", True):
    raise ValueError("This device profile does not include a private key")

device_kwargs = {
    "private_key": base_path / "device_private_key",
    "client_id": base_path / "device_client_id_blob",
    "type_": wv.get("session_id_type", "ANDROID").upper(),
    "security_level": wv.get("security_level", 3),
}

vmp_path = base_path / "device_vmp_blob"
if wv.get("vmp", False) and vmp_path.exists():
    device_kwargs["vmp"] = vmp_path

device = Device.from_files(**device_kwargs)

cdm = Cdm.from_device(device)
session_id = cdm.open()

try:
    challenge = cdm.get_license_challenge(session_id, pssh)

    license_response = requests.post(
        "https://cwip-shaka-proxy.appspot.com/no_auth",
        data=challenge,
    )
    license_response.raise_for_status()

    cdm.parse_license(session_id, license_response.content)

    for key in cdm.get_keys(session_id):
        print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")

finally:
    cdm.close(session_id)
```

---

## Disclaimer

This tool is intended strictly for **educational, research, and interoperability purposes**.
The author does not support or encourage the misuse of DRM systems or unauthorized access to protected content.

---

## Issues and Support

For bug reports, feature requests, or general inquiries, please open an issue in the repository.

Support and updates will be provided as availability permits.

---

## Acknowledgements

This project is **based on pywidevine**, with modifications and restructuring to support standalone usage and extended functionality for working with WVD and PSSH data.
