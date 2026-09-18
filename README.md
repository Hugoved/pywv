# pywv

**pywv** is a Python utility for working with Widevine device files, PSSH data, and local CDM workflows.

It supports WVD files, raw device files, license requests, device export/import, and basic server usage.

---

## Features

- Load and parse WVD files
- Create devices from raw key and client ID files
- Export device files from WVD
- Migrate older WVD files
- Parse and create PSSH data
- Generate license challenges
- Parse license responses
- Optional VMP support
- Single-file Python implementation

---

## Requirements

- Python 3.9+
- `pycryptodome`
- `requests`

Install:

```bash
pip install pycryptodome requests
```

---

## Usage

```bash
python pywv.py <command> [options]
```

Available commands:

```text
license
test
create-device
export-device
migrate
serve
```

Use:

```bash
python pywv.py --help
```

or:

```bash
python pywv.py <command> --help
```

for command-specific options.

---

## License

Example:

```bash
python pywv.py license device.wvd PSSH LICENSE_URL
```

---

## Create Device

Create a device from raw files:

```bash
python pywv.py create-device --help
```

Typical files:

```text
device_private_key
device_client_id_blob
device_vmp_blob
```

---

## Export Device

Export files from a WVD:

```bash
python pywv.py export-device device.wvd
```

---

## Migrate

Migrate an older WVD:

```bash
python pywv.py migrate device.wvd
```

---

## Test

Run the built-in test command:

```bash
python pywv.py test device.wvd
```

---

## Serve

Start the server mode:

```bash
python pywv.py serve --help
```

---

## Python Usage

### Load a WVD

```python
from pywv import Device

device = Device.load("device.wvd")

print(device.system_id)
print(device.security_level)
```

### Load Raw Device Files

```python
from pathlib import Path
from pywv import Device

base = Path(__file__).resolve().parent

device = Device.from_files(
    certificate=base / "device_client_id_blob",
    key=base / "device_private_key",
    vmp=False
)
```

### PSSH

```python
from pywv import PSSH

pssh = PSSH("BASE64_PSSH")

print(pssh.key_ids)
print(pssh.dumps())
```

### CDM

```python
from pywv import Device, Cdm

device = Device.load("device.wvd")

cdm = Cdm.from_device(device)
session_id = cdm.open()

try:
    pass
finally:
    cdm.close(session_id)
```

---

## Notes

- WVD and raw device file loading are supported.
- VMP is optional.
- Raw device files can be used directly through `Device.from_files(...)`.
- Use the built-in command help for the latest CLI arguments.

---

## Disclaimer

This tool is intended for educational, research, interoperability, and authorized testing purposes.

Use it only with devices, services, and content that you are authorized to access.

---

## Acknowledgements

The project is inspired by pywidevine and adapted into a standalone Python implementation.
