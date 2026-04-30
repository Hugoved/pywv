# pywv

**pywv** is a Python-based tool for parsing, analyzing, and interacting with **Widevine (WVD) device files** and DRM structures.
It provides direct access to device data, cryptographic components, and license workflows for controlled inspection and processing.

---

## Features

* Parsing and loading of **Widevine Device (WVD) files**
* Support for **WVD version migration (v1 → v2)**
* Device loading from:

  * `.wvd` files
  * key + client_id blobs
  * device directories
* Extraction of **device attributes** (system ID, security level)
* Decoding of **Widevine protobuf structures**
* Integration with **cryptographic primitives** (RSA, AES, CMAC, HMAC)
* Parsing and manipulation of **Widevine PSSH**
* License processing and **content key extraction**
* Optional **VMP (Verified Media Path) support**
* Built-in CDM logic (no external binaries required)

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
python pywv.py <command> [options]
```

---

## Commands

### info

Inspect a device:

```bash
python pywv.py info --wvd device.wvd
```

Alternative input modes:

```bash
python pywv.py info --device-dir path/
python pywv.py info --key device_private_key --client-id device_client_id_blob
```

Optional:

```bash
--vmp device_vmp_blob
```

---

### license

Execute the full license workflow (challenge generation, request submission, response parsing, key extraction):

```bash
python pywv.py license \
  --wvd device.wvd \
  --pssh BASE64_PSSH \
  --url LICENSE_URL
```

Using raw blobs:

```bash
python pywv.py license \
  --key device_private_key \
  --client-id device_client_id_blob \
  --pssh BASE64_PSSH \
  --url LICENSE_URL
```

Challenge-only mode:

```bash
python pywv.py license \
  --wvd device.wvd \
  --pssh BASE64_PSSH
```

---

### create-wvd

Create a WVD file from raw device components:

```bash
python pywv.py create-wvd \
  --key device_private_key \
  --client-id device_client_id_blob \
  -o device.wvd
```

With VMP:

```bash
--vmp device_vmp_blob
```

---

### export-wvd

Export a WVD file into raw device components:

```bash
python pywv.py export-wvd \
  --wvd device.wvd \
  -o output_dir
```

---

### migrate-wvd

Migrate a WVD v1 file to WVD v2:

```bash
python pywv.py migrate-wvd \
  -i old.wvd \
  -o new.wvd
```

---

### pssh

Inspect PSSH data:

```bash
python pywv.py pssh --pssh BASE64_PSSH
```

Rewrite key IDs:

```bash
python pywv.py pssh --pssh BASE64_PSSH --set-kid NEW_KID
```

---

## Python Usage

### Basic Usage

```python
import requests
from pywv import PSSH, Device, Cdm

pssh = PSSH("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==")

device = Device.load("device.wvd")

cdm = Cdm.from_device(device)
session_id = cdm.open()

try:
    challenge = cdm.get_license_challenge(session_id, pssh)

    response = requests.post(
        "https://cwip-shaka-proxy.appspot.com/no_auth",
        data=challenge,
    )
    response.raise_for_status()

    cdm.parse_license(session_id, response.content)

    for key in cdm.get_keys(session_id):
        print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")

finally:
    cdm.close(session_id)
```

---

### Using Key / Certificate (no JSON)

```python
import requests
from pathlib import Path
from pywv import PSSH, Device, Cdm

base = Path(__file__).resolve().parent

pssh = PSSH("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==")

device = Device.from_files(
    certificate=base / "device_client_id_blob",
    key=base / "device_private_key",
    vmp=False
)

cdm = Cdm.from_device(device)
session_id = cdm.open()

try:
    challenge = cdm.get_license_challenge(session_id, pssh)

    response = requests.post(
        "https://cwip-shaka-proxy.appspot.com/no_auth",
        data=challenge,
    )
    response.raise_for_status()

    cdm.parse_license(session_id, response.content)

    for key in cdm.get_keys(session_id):
        print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")

finally:
    cdm.close(session_id)
```

### Create WVD

```python
from pywv import Device

device = Device.from_files(
    certificate="device_client_id_blob",
    key="device_private_key",
    vmp=False
)

device.dump("device.wvd")
```

---

### Export WVD

```python
from pathlib import Path
from pywv import Device

out = Path("exported")
out.mkdir(exist_ok=True)

device = Device.load("device.wvd")

(out / "device_private_key").write_bytes(
    device.private_key.export_key("DER")
)

(out / "device_client_id_blob").write_bytes(
    device.client_id.SerializeToString()
)

if device.client_id.vmp_data:
    (out / "device_vmp_blob").write_bytes(
        device.client_id.vmp_data
    )
```

---

### Migrate WVD v1 → v2

```python
from pywv import Device

with open("old.wvd", "rb") as f:
    data = f.read()

device = Device.migrate(data)
device.dump("new.wvd")
```

---

### PSSH

```python
from pywv import PSSH

pssh = PSSH("BASE64")

print(pssh.key_ids)

new_pssh = PSSH.new(
    system_id=PSSH.SystemId.Widevine,
    key_ids=pssh.key_ids,
    version=1
)

print(new_pssh.dumps())
```

---

## Output

```
[CONTENT] kid:key
```

---

## Disclaimer

This tool is intended strictly for **educational, research, and interoperability purposes**.
The author does not support or encourage misuse of DRM systems or unauthorized access to protected content.

---

## Issues and Support

For bug reports, feature requests, or general inquiries, please open an issue in the repository.

---

## Acknowledgements

This project is based on **pywidevine**, adapted for standalone usage and improved WVD and PSSH workflows.
