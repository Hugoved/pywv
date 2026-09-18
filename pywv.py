from __future__ import annotations
import argparse
import base64
import binascii
import json
import logging
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
import unicodedata
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union
from uuid import UUID
from zlib import crc32
import requests
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import CMAC, HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util import Padding as CryptoPadding

__version__ = "2.1.0"

class DecodeError(ValueError):
    pass

class _EnumMap:
    def __init__(self, mapping):
        self._name_to_value = dict(mapping)
        self._value_to_name = {value: name for name, value in self._name_to_value.items()}

    def Value(self, name):
        if isinstance(name, int):
            if name not in self._value_to_name:
                raise ValueError(f"Unknown enum value: {name}")
            return name
        try:
            return self._name_to_value[name]
        except KeyError as exc:
            raise ValueError(f"Unknown enum name: {name}") from exc

    def Name(self, value):
        try:
            return self._value_to_name[int(value)]
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"Unknown enum value: {value}") from exc

    def keys(self):
        return list(self._name_to_value.keys())

    def values(self):
        return list(self._name_to_value.values())

    def items(self):
        return list(self._name_to_value.items())

    def __getattr__(self, name):
        if name in self._name_to_value:
            return self._name_to_value[name]
        raise AttributeError(name)

class _FieldSpec:
    __slots__ = ("number", "kind", "repeated", "message", "enum", "default")

    def __init__(self, number, kind, repeated=False, message=None, enum=None, default=None):
        self.number = number
        self.kind = kind
        self.repeated = repeated
        self.message = message
        self.enum = enum
        self.default = default

class _FieldDescriptor:
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

class _TrackedList(list):
    def __init__(self, iterable=(), callback=None):
        super().__init__(iterable)
        self._callback = callback

    def _changed(self):
        if self._callback:
            self._callback()

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._changed()

    def __delitem__(self, key):
        super().__delitem__(key)
        self._changed()

    def append(self, value):
        super().append(value)
        self._changed()

    def extend(self, values):
        super().extend(values)
        self._changed()

    def insert(self, index, value):
        super().insert(index, value)
        self._changed()

    def pop(self, index=-1):
        value = super().pop(index)
        self._changed()
        return value

    def remove(self, value):
        super().remove(value)
        self._changed()

    def clear(self):
        super().clear()
        self._changed()

    def reverse(self):
        super().reverse()
        self._changed()

    def sort(self, *args, **kwargs):
        super().sort(*args, **kwargs)
        self._changed()

    def __iadd__(self, values):
        result = super().__iadd__(values)
        self._changed()
        return result

def _encode_varint(value):
    value = int(value)
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)

def _decode_varint(data, offset):
    value = 0
    shift = 0
    start = offset
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, offset
        shift += 7
    raise DecodeError(f"Invalid varint at offset {start}")

def _wire_key(number, wire_type):
    return _encode_varint((number << 3) | wire_type)

def _field(number, kind, repeated=False, message=None, enum=None, default=None):
    return _FieldSpec(number, kind, repeated, message, enum, default)

class _ProtoMessage:
    _schema = {}

    def __init__(self, **kwargs):
        object.__setattr__(self, "_initializing", True)
        object.__setattr__(self, "_present_fields", set())
        object.__setattr__(self, "_unknown_fields", [])
        object.__setattr__(self, "_original_bytes", None)
        object.__setattr__(self, "_dirty", False)
        self._set_defaults()
        for name, value in kwargs.items():
            if name not in self._schema:
                raise TypeError(f"Unknown field {name!r} for {self.__class__.__name__}")
            self._assign_field(name, value, present=True, dirty=False)
        object.__setattr__(self, "_initializing", False)
        if kwargs:
            object.__setattr__(self, "_dirty", True)

    def _set_defaults(self):
        for name, spec in self._schema.items():
            if spec.repeated:
                value = _TrackedList(callback=self._mark_dirty)
            elif spec.kind == "msg":
                value = None
            elif spec.default is not None:
                value = spec.default
            elif spec.kind == "bytes":
                value = b""
            elif spec.kind == "string":
                value = ""
            elif spec.kind == "bool":
                value = False
            else:
                value = 0
            object.__setattr__(self, name, value)

    def _reset(self):
        object.__setattr__(self, "_initializing", True)
        object.__setattr__(self, "_present_fields", set())
        object.__setattr__(self, "_unknown_fields", [])
        object.__setattr__(self, "_original_bytes", None)
        object.__setattr__(self, "_dirty", False)
        self._set_defaults()
        object.__setattr__(self, "_initializing", False)

    def _mark_dirty(self):
        if not getattr(self, "_initializing", False):
            object.__setattr__(self, "_dirty", True)

    def _normalize_value(self, spec, value):
        if spec.kind == "enum":
            if isinstance(value, str):
                return spec.enum.Value(value)
            return int(value)
        if spec.kind in ("uint", "int"):
            return int(value)
        if spec.kind == "bool":
            return bool(value)
        if spec.kind == "bytes":
            if isinstance(value, bytearray):
                return bytes(value)
            if not isinstance(value, bytes):
                raise TypeError(f"Expected bytes, got {type(value).__name__}")
            return value
        if spec.kind == "string":
            if not isinstance(value, str):
                value = str(value)
            return value
        if spec.kind == "msg":
            if value is None:
                return spec.message()
            if isinstance(value, spec.message):
                return value
            if isinstance(value, dict):
                return spec.message(**value)
            raise TypeError(f"Expected {spec.message.__name__}, got {type(value).__name__}")
        return value

    def _assign_field(self, name, value, present=True, dirty=True):
        spec = self._schema[name]
        if not spec.repeated and spec.kind == "msg" and value is None:
            object.__setattr__(self, name, None)
            self._present_fields.discard(name)
            if dirty and not self._initializing:
                object.__setattr__(self, "_dirty", True)
            return
        if spec.repeated:
            if value is None:
                normalized = []
            else:
                normalized = [self._normalize_value(_FieldSpec(spec.number, spec.kind, False, spec.message, spec.enum, spec.default), item) for item in value]
            value = _TrackedList(normalized, callback=self._mark_dirty)
        else:
            value = self._normalize_value(spec, value)
        object.__setattr__(self, name, value)
        if present:
            self._present_fields.add(name)
        else:
            self._present_fields.discard(name)
        if dirty and not self._initializing:
            object.__setattr__(self, "_dirty", True)

    def __getattribute__(self, name):
        if not name.startswith("_"):
            schema = object.__getattribute__(self, "_schema")
            spec = schema.get(name)
            if spec is not None and not spec.repeated and spec.kind == "msg":
                value = object.__getattribute__(self, name)
                if value is None:
                    value = spec.message()
                    object.__setattr__(self, name, value)
                return value
        return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        if name in getattr(self, "_schema", {}):
            self._assign_field(name, value, present=True, dirty=True)
        else:
            object.__setattr__(self, name, value)

    @staticmethod
    def _expected_wire(spec):
        if spec.kind in ("uint", "int", "bool", "enum"):
            return 0
        return 2

    def ParseFromString(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("ParseFromString expects bytes-like input")
        data = bytes(data)
        self._reset()
        object.__setattr__(self, "_initializing", True)
        by_number = {spec.number: (name, spec) for name, spec in self._schema.items()}
        offset = 0
        while offset < len(data):
            start = offset
            key, offset = _decode_varint(data, offset)
            number = key >> 3
            wire_type = key & 7
            if number == 0:
                raise DecodeError("Invalid field number 0")
            if wire_type == 0:
                raw_value, offset = _decode_varint(data, offset)
                payload = raw_value
            elif wire_type == 1:
                if offset + 8 > len(data):
                    raise DecodeError("Truncated fixed64 field")
                payload = data[offset:offset + 8]
                offset += 8
            elif wire_type == 2:
                length, offset = _decode_varint(data, offset)
                end = offset + length
                if end > len(data):
                    raise DecodeError("Truncated length-delimited field")
                payload = data[offset:end]
                offset = end
            elif wire_type == 5:
                if offset + 4 > len(data):
                    raise DecodeError("Truncated fixed32 field")
                payload = data[offset:offset + 4]
                offset += 4
            else:
                raise DecodeError(f"Unsupported wire type {wire_type}")
            raw_chunk = data[start:offset]
            match = by_number.get(number)
            if not match:
                self._unknown_fields.append(raw_chunk)
                continue
            name, spec = match
            expected = self._expected_wire(spec)
            if spec.repeated and expected == 0 and wire_type == 2:
                packed_offset = 0
                values = []
                while packed_offset < len(payload):
                    item, packed_offset = _decode_varint(payload, packed_offset)
                    values.append(item)
                target = getattr(self, name)
                target.extend(self._decode_scalar(spec, item) for item in values)
                self._present_fields.add(name)
                continue
            if wire_type != expected:
                raise DecodeError(f"Wire type mismatch for {self.__class__.__name__}.{name}")
            value = self._decode_payload(spec, payload)
            if spec.repeated:
                getattr(self, name).append(value)
                self._present_fields.add(name)
            else:
                object.__setattr__(self, name, value)
                self._present_fields.add(name)
        object.__setattr__(self, "_initializing", False)
        object.__setattr__(self, "_original_bytes", data)
        object.__setattr__(self, "_dirty", False)
        return None

    def _decode_scalar(self, spec, payload):
        if spec.kind == "bool":
            return bool(payload)
        if spec.kind in ("uint", "int", "enum"):
            return int(payload)
        return payload

    def _decode_payload(self, spec, payload):
        if spec.kind in ("uint", "int", "bool", "enum"):
            return self._decode_scalar(spec, payload)
        if spec.kind == "bytes":
            return bytes(payload)
        if spec.kind == "string":
            try:
                return bytes(payload).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DecodeError(f"Invalid UTF-8 in string field: {exc}") from exc
        if spec.kind == "msg":
            value = spec.message()
            value.ParseFromString(payload)
            return value
        raise DecodeError(f"Unsupported field kind {spec.kind}")

    def _has_nested_changes(self):
        for name, spec in self._schema.items():
            if name not in self._present_fields:
                continue
            value = getattr(self, name)
            if spec.kind == "msg":
                if spec.repeated:
                    if any(item._dirty or item._has_nested_changes() for item in value):
                        return True
                elif value._dirty or value._has_nested_changes():
                    return True
        return False

    def SerializeToString(self):
        if self._original_bytes is not None and not self._dirty and not self._has_nested_changes():
            return self._original_bytes
        out = bytearray()
        ordered = sorted(self._schema.items(), key=lambda item: item[1].number)
        for name, spec in ordered:
            if name not in self._present_fields:
                continue
            value = getattr(self, name)
            values = value if spec.repeated else [value]
            for item in values:
                out.extend(self._encode_field(spec, item))
        for raw in self._unknown_fields:
            out.extend(raw)
        return bytes(out)

    def _encode_field(self, spec, value):
        if spec.kind in ("uint", "int", "bool", "enum"):
            return _wire_key(spec.number, 0) + _encode_varint(int(value))
        if spec.kind == "bytes":
            payload = bytes(value)
        elif spec.kind == "string":
            payload = str(value).encode("utf-8")
        elif spec.kind == "msg":
            payload = value.SerializeToString()
        else:
            raise TypeError(f"Unsupported field kind {spec.kind}")
        return _wire_key(spec.number, 2) + _encode_varint(len(payload)) + payload

    def CopyFrom(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError(f"Expected {self.__class__.__name__}")
        self.ParseFromString(other.SerializeToString())

    def HasField(self, name):
        if name not in self._schema:
            raise ValueError(f"Unknown field {name}")
        return name in self._present_fields

    def ListFields(self):
        items = []
        for name, spec in sorted(self._schema.items(), key=lambda item: item[1].number):
            if name not in self._present_fields:
                continue
            value = getattr(self, name)
            if spec.repeated and not value:
                continue
            items.append((_FieldDescriptor(name), value))
        return items

    def to_dict(self):
        result = {}
        for name, spec in sorted(self._schema.items(), key=lambda item: item[1].number):
            if name not in self._present_fields:
                continue
            value = getattr(self, name)
            if spec.repeated:
                result[name] = [self._dict_value(spec, item) for item in value]
            else:
                result[name] = self._dict_value(spec, value)
        return result

    def _dict_value(self, spec, value):
        if spec.kind == "msg":
            return value.to_dict()
        if spec.kind == "enum":
            try:
                return spec.enum.Name(value)
            except ValueError:
                return value
        if spec.kind == "bytes":
            return base64.b64encode(value).decode()
        return value

    def __repr__(self):
        fields = ", ".join(f"{name}={getattr(self, name)!r}" for name in self._present_fields)
        return f"{self.__class__.__name__}({fields})"

def _message_to_dict(message):
    if not isinstance(message, _ProtoMessage):
        raise TypeError(f"Unsupported message type: {type(message).__name__}")
    return message.to_dict()

def _license_type_enum() -> _EnumMap:
    return _EnumMap({"STREAMING": 1, "OFFLINE": 2, "AUTOMATIC": 3})


def _platform_verification_status_enum() -> _EnumMap:
    return _EnumMap({
        "PLATFORM_UNVERIFIED": 0,
        "PLATFORM_TAMPERED": 1,
        "PLATFORM_SOFTWARE_VERIFIED": 2,
        "PLATFORM_HARDWARE_VERIFIED": 3,
        "PLATFORM_NO_VERIFICATION": 4,
        "PLATFORM_SECURE_STORAGE_SOFTWARE_VERIFIED": 5,
    })


def _protocol_version_enum() -> _EnumMap:
    return _EnumMap({"VERSION_2_0": 20, "VERSION_2_1": 21, "VERSION_2_2": 22})


def _hash_algorithm_enum() -> _EnumMap:
    return _EnumMap({
        "HASH_ALGORITHM_UNSPECIFIED": 0,
        "HASH_ALGORITHM_SHA_1": 1,
        "HASH_ALGORITHM_SHA_256": 2,
        "HASH_ALGORITHM_SHA_384": 3,
    })


def _key_type_enum() -> _EnumMap:
    return _EnumMap({
        "SIGNING": 1,
        "CONTENT": 2,
        "KEY_CONTROL": 3,
        "OPERATOR_SESSION": 4,
        "ENTITLEMENT": 5,
        "OEM_CONTENT": 6,
    })


def _security_level_enum() -> _EnumMap:
    return _EnumMap({
        "SW_SECURE_CRYPTO": 1,
        "SW_SECURE_DECODE": 2,
        "HW_SECURE_CRYPTO": 3,
        "HW_SECURE_DECODE": 4,
        "HW_SECURE_ALL": 5,
    })


def _request_type_enum() -> _EnumMap:
    return _EnumMap({"NEW": 1, "RENEWAL": 2, "RELEASE": 3})


def _message_type_enum() -> _EnumMap:
    return _EnumMap({
        "LICENSE_REQUEST": 1,
        "LICENSE": 2,
        "ERROR_RESPONSE": 3,
        "SERVICE_CERTIFICATE_REQUEST": 4,
        "SERVICE_CERTIFICATE": 5,
        "SUB_LICENSE": 6,
        "CAS_LICENSE_REQUEST": 7,
        "CAS_LICENSE": 8,
        "EXTERNAL_LICENSE_REQUEST": 9,
        "EXTERNAL_LICENSE": 10,
    })


def _session_key_type_enum() -> _EnumMap:
    return _EnumMap({"UNDEFINED": 0, "WRAPPED_AES_KEY": 1, "EPHERMERAL_ECC_PUBLIC_KEY": 2})


def _token_type_enum() -> _EnumMap:
    return _EnumMap({
        "KEYBOX": 0,
        "DRM_DEVICE_CERTIFICATE": 1,
        "REMOTE_ATTESTATION_CERTIFICATE": 2,
        "OEM_DEVICE_CERTIFICATE": 3,
    })


def _hdcp_version_enum() -> _EnumMap:
    return _EnumMap({
        "HDCP_NONE": 0,
        "HDCP_V1": 1,
        "HDCP_V2": 2,
        "HDCP_V2_1": 3,
        "HDCP_V2_2": 4,
        "HDCP_V2_3": 5,
        "HDCP_NO_DIGITAL_OUTPUT": 255,
    })


def _certificate_key_type_enum() -> _EnumMap:
    return _EnumMap({
        "RSA_2048": 0,
        "RSA_3072": 1,
        "ECC_SECP256R1": 2,
        "ECC_SECP384R1": 3,
        "ECC_SECP521R1": 4,
    })


def _analog_output_capabilities_enum() -> _EnumMap:
    return _EnumMap({
        "ANALOG_OUTPUT_UNKNOWN": 0,
        "ANALOG_OUTPUT_NONE": 1,
        "ANALOG_OUTPUT_SUPPORTED": 2,
        "ANALOG_OUTPUT_SUPPORTS_CGMS_A": 3,
    })


def _drm_certificate_type_enum() -> _EnumMap:
    return _EnumMap({"ROOT": 0, "DEVICE_MODEL": 1, "DEVICE": 2, "SERVICE": 3, "PROVISIONER": 4})


def _drm_service_type_enum() -> _EnumMap:
    return _EnumMap({
        "UNKNOWN_SERVICE_TYPE": 0,
        "LICENSE_SERVER_SDK": 1,
        "LICENSE_SERVER_PROXY_SDK": 2,
        "PROVISIONING_SDK": 3,
        "CAS_PROXY_SDK": 4,
    })


def _drm_algorithm_enum() -> _EnumMap:
    return _EnumMap({
        "UNKNOWN_ALGORITHM": 0,
        "RSA": 1,
        "ECC_SECP256R1": 2,
        "ECC_SECP384R1": 3,
        "ECC_SECP521R1": 4,
    })


def _widevine_pssh_type_enum() -> _EnumMap:
    return _EnumMap({"SINGLE": 0, "ENTITLEMENT": 1, "ENTITLED_KEY": 2})


def _widevine_pssh_algorithm_enum() -> _EnumMap:
    return _EnumMap({"UNENCRYPTED": 0, "AESCTR": 1})

class LicenseIdentification(_ProtoMessage):
    pass

LicenseIdentification._schema = {
    "request_id": _field(1, "bytes"),
    "session_id": _field(2, "bytes"),
    "purchase_id": _field(3, "bytes"),
    "type": _field(4, "enum", enum=_license_type_enum(), default=1),
    "version": _field(5, "int"),
    "provider_session_token": _field(6, "bytes"),
}


class OperatorSessionKeyPermissions(_ProtoMessage):
    pass

OperatorSessionKeyPermissions._schema = {
    "allow_encrypt": _field(1, "bool"),
    "allow_decrypt": _field(2, "bool"),
    "allow_sign": _field(3, "bool"),
    "allow_signature_verify": _field(4, "bool"),
}


class LicenseKeyContainer(_ProtoMessage):
    pass

LicenseKeyContainer.KeyType = _key_type_enum()
LicenseKeyContainer.SecurityLevel = _security_level_enum()
LicenseKeyContainer._schema = {
    "id": _field(1, "bytes"),
    "iv": _field(2, "bytes"),
    "key": _field(3, "bytes"),
    "type": _field(4, "enum", enum=LicenseKeyContainer.KeyType, default=1),
    "level": _field(5, "enum", enum=LicenseKeyContainer.SecurityLevel, default=1),
    "operator_session_key_permissions": _field(9, "msg", message=OperatorSessionKeyPermissions),
    "anti_rollback_usage_table": _field(11, "bool"),
    "track_label": _field(12, "string"),
}


class License(_ProtoMessage):
    pass

License._schema = {
    "id": _field(1, "msg", message=LicenseIdentification),
    "key": _field(3, "msg", repeated=True, message=LicenseKeyContainer),
    "license_start_time": _field(4, "int"),
    "remote_attestation_verified": _field(5, "bool"),
    "provider_client_token": _field(6, "bytes"),
    "protection_scheme": _field(7, "uint"),
    "srm_requirement": _field(8, "bytes"),
    "srm_update": _field(9, "bytes"),
    "platform_verification_status": _field(10, "enum", enum=_platform_verification_status_enum(), default=4),
    "group_ids": _field(11, "bytes", repeated=True),
}
License.KeyContainer = LicenseKeyContainer


class LicenseRequestWidevinePsshData(_ProtoMessage):
    pass

LicenseRequestWidevinePsshData._schema = {
    "pssh_data": _field(1, "bytes", repeated=True),
    "license_type": _field(2, "enum", enum=_license_type_enum(), default=1),
    "request_id": _field(3, "bytes"),
}


class LicenseRequestContentIdentification(_ProtoMessage):
    pass

LicenseRequestContentIdentification._schema = {
    "widevine_pssh_data": _field(1, "msg", message=LicenseRequestWidevinePsshData),
}
LicenseRequestContentIdentification.WidevinePsshData = LicenseRequestWidevinePsshData


class EncryptedClientIdentification(_ProtoMessage):
    pass

EncryptedClientIdentification._schema = {
    "provider_id": _field(1, "string"),
    "service_certificate_serial_number": _field(2, "bytes"),
    "encrypted_client_id": _field(3, "bytes"),
    "encrypted_client_id_iv": _field(4, "bytes"),
    "encrypted_privacy_key": _field(5, "bytes"),
}


class LicenseRequest(_ProtoMessage):
    pass

LicenseRequest.RequestType = _request_type_enum()
LicenseRequest.ContentIdentification = LicenseRequestContentIdentification


class SignedMessage(_ProtoMessage):
    pass

SignedMessage.MessageType = _message_type_enum()
SignedMessage.SessionKeyType = _session_key_type_enum()
SignedMessage._schema = {
    "type": _field(1, "enum", enum=SignedMessage.MessageType),
    "msg": _field(2, "bytes"),
    "signature": _field(3, "bytes"),
    "session_key": _field(4, "bytes"),
    "remote_attestation": _field(5, "bytes"),
    "session_key_type": _field(8, "enum", enum=SignedMessage.SessionKeyType, default=1),
    "oemcrypto_core_message": _field(9, "bytes"),
}


class ClientNameValue(_ProtoMessage):
    pass

ClientNameValue._schema = {
    "name": _field(1, "string"),
    "value": _field(2, "string"),
}


class ClientCapabilities(_ProtoMessage):
    pass

ClientCapabilities.HdcpVersion = _hdcp_version_enum()
ClientCapabilities.CertificateKeyType = _certificate_key_type_enum()
ClientCapabilities.AnalogOutputCapabilities = _analog_output_capabilities_enum()
ClientCapabilities._schema = {
    "client_token": _field(1, "bool"),
    "session_token": _field(2, "bool"),
    "video_resolution_constraints": _field(3, "bool"),
    "max_hdcp_version": _field(4, "enum", enum=ClientCapabilities.HdcpVersion),
    "oem_crypto_api_version": _field(5, "uint"),
    "anti_rollback_usage_table": _field(6, "bool"),
    "srm_version": _field(7, "uint"),
    "can_update_srm": _field(8, "bool"),
    "supported_certificate_key_type": _field(9, "enum", repeated=True, enum=ClientCapabilities.CertificateKeyType),
    "analog_output_capabilities": _field(10, "enum", enum=ClientCapabilities.AnalogOutputCapabilities),
    "can_disable_analog_output": _field(11, "bool"),
    "resource_rating_tier": _field(12, "uint"),
}


class ClientCredentials(_ProtoMessage):
    pass

ClientCredentials.TokenType = _token_type_enum()
ClientCredentials._schema = {
    "type": _field(1, "enum", enum=ClientCredentials.TokenType),
    "token": _field(2, "bytes"),
}


class ClientIdentification(_ProtoMessage):
    pass

ClientIdentification.TokenType = _token_type_enum()
ClientIdentification.NameValue = ClientNameValue
ClientIdentification.ClientCapabilities = ClientCapabilities
ClientIdentification.ClientCredentials = ClientCredentials
ClientIdentification._schema = {
    "type": _field(1, "enum", enum=ClientIdentification.TokenType),
    "token": _field(2, "bytes"),
    "client_info": _field(3, "msg", repeated=True, message=ClientNameValue),
    "provider_client_token": _field(4, "bytes"),
    "license_counter": _field(5, "uint"),
    "client_capabilities": _field(6, "msg", message=ClientCapabilities),
    "vmp_data": _field(7, "bytes"),
    "device_credentials": _field(8, "msg", repeated=True, message=ClientCredentials),
}


class DrmEncryptionKey(_ProtoMessage):
    pass

DrmEncryptionKey.Algorithm = _drm_algorithm_enum()
DrmEncryptionKey._schema = {
    "public_key": _field(1, "bytes"),
    "algorithm": _field(2, "enum", enum=DrmEncryptionKey.Algorithm, default=1),
}


class DrmCertificate(_ProtoMessage):
    pass

DrmCertificate.Type = _drm_certificate_type_enum()
DrmCertificate.ServiceType = _drm_service_type_enum()
DrmCertificate.Algorithm = _drm_algorithm_enum()
DrmCertificate.EncryptionKey = DrmEncryptionKey
DrmCertificate._schema = {
    "type": _field(1, "enum", enum=DrmCertificate.Type),
    "serial_number": _field(2, "bytes"),
    "creation_time_seconds": _field(3, "uint"),
    "public_key": _field(4, "bytes"),
    "system_id": _field(5, "uint"),
    "test_device_deprecated": _field(6, "bool"),
    "provider_id": _field(7, "string"),
    "service_types": _field(8, "enum", repeated=True, enum=DrmCertificate.ServiceType),
    "algorithm": _field(9, "enum", enum=DrmCertificate.Algorithm, default=1),
    "rot_id": _field(10, "bytes"),
    "encryption_key": _field(11, "msg", message=DrmEncryptionKey),
    "expiration_time_seconds": _field(12, "uint"),
}


class SignedDrmCertificate(_ProtoMessage):
    pass


class WidevineEntitledKey(_ProtoMessage):
    pass

WidevineEntitledKey._schema = {
    "entitlement_key_id": _field(1, "bytes"),
    "key_id": _field(2, "bytes"),
    "key": _field(3, "bytes"),
    "iv": _field(4, "bytes"),
    "entitlement_key_size_bytes": _field(5, "uint", default=32),
}


class WidevinePsshData(_ProtoMessage):
    pass

WidevinePsshData.Type = _widevine_pssh_type_enum()
WidevinePsshData.Algorithm = _widevine_pssh_algorithm_enum()
WidevinePsshData.EntitledKey = WidevineEntitledKey
WidevinePsshData._schema = {
    "algorithm": _field(1, "enum", enum=WidevinePsshData.Algorithm),
    "key_ids": _field(2, "bytes", repeated=True),
    "provider": _field(3, "string"),
    "content_id": _field(4, "bytes"),
    "track_type": _field(5, "string"),
    "policy": _field(6, "string"),
    "crypto_period_index": _field(7, "uint"),
    "grouped_license": _field(8, "bytes"),
    "protection_scheme": _field(9, "uint"),
    "crypto_period_seconds": _field(10, "uint"),
    "type": _field(11, "enum", enum=WidevinePsshData.Type),
    "key_sequence": _field(12, "uint"),
    "group_ids": _field(13, "bytes", repeated=True),
    "entitled_keys": _field(14, "msg", repeated=True, message=WidevineEntitledKey),
    "video_feature": _field(15, "string"),
}


class FileHashSignature(_ProtoMessage):
    pass

FileHashSignature._schema = {
    "filename": _field(1, "string"),
    "test_signing": _field(2, "bool"),
    "SHA512Hash": _field(3, "bytes"),
    "main_exe": _field(4, "bool"),
    "signature": _field(5, "bytes"),
}


class FileHashes(_ProtoMessage):
    pass

FileHashes.Signature = FileHashSignature
FileHashes._schema = {
    "signer": _field(1, "bytes"),
    "signatures": _field(2, "msg", repeated=True, message=FileHashSignature),
}

SignedDrmCertificate._schema = {
    "drm_certificate": _field(1, "bytes"),
    "signature": _field(2, "bytes"),
    "signer": _field(3, "msg", message=SignedDrmCertificate),
    "hash_algorithm": _field(4, "enum", enum=_hash_algorithm_enum()),
}

LicenseRequest._schema = {
    "client_id": _field(1, "msg", message=ClientIdentification),
    "content_id": _field(2, "msg", message=LicenseRequestContentIdentification),
    "type": _field(3, "enum", enum=LicenseRequest.RequestType),
    "request_time": _field(4, "int"),
    "key_control_nonce_deprecated": _field(5, "bytes"),
    "protocol_version": _field(6, "enum", enum=_protocol_version_enum(), default=20),
    "key_control_nonce": _field(7, "uint"),
    "encrypted_client_id": _field(8, "msg", message=EncryptedClientIdentification),
}

class Exception(Exception):
    """Exceptions used by ."""

class TooManySessions(Exception):
    """Too many Sessions are open."""

class InvalidSession(Exception):
    """No Session is open with the specified identifier."""

class InvalidInitData(Exception):
    """The Widevine Cenc Header Data is invalid or empty."""

class InvalidLicenseType(Exception):
    """The License Type is an Invalid Value."""

class InvalidLicenseMessage(Exception):
    """The License Message is Invalid or Missing."""

class InvalidContext(Exception):
    """The Context is Invalid or Missing."""


class SignatureMismatch(Exception):
    """The Signature did not match."""


class NoKeysLoaded(Exception):
    """No License was parsed for this Session, No Keys available."""


class DeviceMismatch(Exception):
    """The Remote CDMs Device information and the APIs Device information did not match."""

class Key:
    def __init__(self, type_: str, kid: UUID, key: bytes, permissions: Optional[list[str]] = None):
        self.type = type_
        self.kid = kid
        self.key = key
        self.permissions = permissions or []

    def __repr__(self) -> str:
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join([f"{k}={repr(v)}" for k, v in self.__dict__.items()])
        )

    @classmethod
    def from_key_container(cls, key: License.KeyContainer, enc_key: bytes) -> Key:
        """Load Key from a KeyContainer object."""
        permissions = []
        if key.type == License.KeyContainer.KeyType.Value("OPERATOR_SESSION"):
            for descriptor, value in key.operator_session_key_permissions.ListFields():
                if value == 1:
                    permissions.append(descriptor.name)

        return Key(
            type_=License.KeyContainer.KeyType.Name(key.type),
            kid=cls.kid_to_uuid(key.id),
            key=CryptoPadding.unpad(
                AES.new(enc_key, AES.MODE_CBC, iv=key.iv).decrypt(key.key),
                16
            ),
            permissions=permissions
        )

    @staticmethod
    def kid_to_uuid(kid: Union[str, bytes]) -> UUID:
        """
        Convert a Key ID from a string or bytes to a UUID object.
        At first this may seem very simple but some types of Key IDs
        may not be 16 bytes and some may be decimal vs. hex.
        """
        if isinstance(kid, str):
            kid = base64.b64decode(kid)
        if not kid:
            kid = b"\x00" * 16

        if kid.decode(errors="replace").isdigit():
            return UUID(int=int(kid.decode()))

        if len(kid) < 16:
            kid += b"\x00" * (16 - len(kid))

        return UUID(bytes=kid)

__all__ = ("Key",)

class Session:
    def __init__(self, number: int):
        self.number = number
        self.id = get_random_bytes(16)
        self.service_certificate: Optional[SignedDrmCertificate] = None
        self.context: dict[bytes, tuple[bytes, bytes]] = {}
        self.keys: list[Key] = []

__all__ = ("Session",)

class DeviceTypes(Enum):
    CHROME = 1
    ANDROID = 2

class _WVDRecord(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


class _WVDHeaderStructure:
    @staticmethod
    def parse(data):
        data = bytes(data)
        if len(data) < 4 or data[:3] != b"WVD":
            raise ValueError("Device Data does not seem to be a WVD file.")
        return _WVDRecord(signature=b"WVD", version=data[3])


class _WVDStructure:
    def __init__(self, version):
        self.version = int(version)

    @staticmethod
    def _read_u16(data, offset):
        if offset + 2 > len(data):
            raise ValueError("Truncated WVD length field.")
        return int.from_bytes(data[offset:offset + 2], "big"), offset + 2

    def parse(self, data):
        data = bytes(data)
        if len(data) < 9 or data[:3] != b"WVD":
            raise ValueError("Invalid or truncated WVD data.")
        version = data[3]
        if version != self.version:
            raise ValueError(f"Expected WVD v{self.version}, got v{version}.")
        try:
            type_ = DeviceTypes(data[4])
        except ValueError as exc:
            raise ValueError(f"Unknown WVD device type: {data[4]}") from exc
        security_level = data[5]
        flag_byte = data[6]
        offset = 7
        private_key_len, offset = self._read_u16(data, offset)
        end = offset + private_key_len
        if end > len(data):
            raise ValueError("Truncated WVD private key.")
        private_key = data[offset:end]
        offset = end
        client_id_len, offset = self._read_u16(data, offset)
        end = offset + client_id_len
        if end > len(data):
            raise ValueError("Truncated WVD client ID.")
        client_id = data[offset:end]
        offset = end
        record = _WVDRecord(
            signature=b"WVD",
            version=version,
            type_=type_,
            security_level=security_level,
            flags={} if flag_byte == 0 else {"raw": flag_byte},
            private_key_len=private_key_len,
            private_key=private_key,
            client_id_len=client_id_len,
            client_id=client_id,
        )
        if version == 1:
            vmp_len, offset = self._read_u16(data, offset)
            end = offset + vmp_len
            if end > len(data):
                raise ValueError("Truncated WVD VMP data.")
            record.vmp_len = vmp_len
            record.vmp = data[offset:end]
            offset = end
        if offset != len(data):
            raise ValueError(f"Unexpected trailing WVD data: {len(data) - offset} bytes.")
        return record

    def parse_stream(self, stream):
        return self.parse(stream.read())

    def build(self, values):
        version = self.version
        type_value = values.get("type_", DeviceTypes.ANDROID)
        if isinstance(type_value, DeviceTypes):
            type_value = type_value.value
        elif isinstance(type_value, str):
            type_value = DeviceTypes[type_value.upper()].value
        type_value = int(type_value)
        security_level = int(values.get("security_level", 3))
        flags = values.get("flags") or {}
        flag_byte = int(flags.get("raw", 0)) if isinstance(flags, dict) else 0
        private_key = bytes(values.get("private_key") or b"")
        client_id = bytes(values.get("client_id") or b"")
        if len(private_key) > 0xFFFF or len(client_id) > 0xFFFF:
            raise ValueError("WVD private key or client ID exceeds 65535 bytes.")
        out = bytearray(b"WVD")
        out.extend((version, type_value, security_level, flag_byte & 0xFF))
        out.extend(len(private_key).to_bytes(2, "big"))
        out.extend(private_key)
        out.extend(len(client_id).to_bytes(2, "big"))
        out.extend(client_id)
        if version == 1:
            vmp = values.get("vmp") or b""
            if isinstance(vmp, FileHashes):
                vmp = vmp.SerializeToString()
            vmp = bytes(vmp)
            if len(vmp) > 0xFFFF:
                raise ValueError("WVD VMP exceeds 65535 bytes.")
            out.extend(len(vmp).to_bytes(2, "big"))
            out.extend(vmp)
        return bytes(out)


class _Structures:
    header = _WVDHeaderStructure()
    v2 = _WVDStructure(2)
    v1 = _WVDStructure(1)

class Device:
    Structures = _Structures
    supported_structure = Structures.v2

    def __init__(self, *_: Any, type_: DeviceTypes, security_level: int, flags: Optional[dict], private_key: Optional[bytes], client_id: Optional[bytes], **__: Any):                                       

        if not client_id:
            raise ValueError("Client ID is required, the WVD does not contain one or is malformed.")
        if not private_key:
            raise ValueError("Private Key is required, the WVD does not contain one or is malformed.")

        self.type = DeviceTypes[type_] if isinstance(type_, str) else type_
        self.security_level = security_level
        self.flags = flags or {}
        self.private_key = RSA.importKey(private_key)
        self.client_id = ClientIdentification()
        try:
            self.client_id.ParseFromString(client_id)
            if self.client_id.SerializeToString() != client_id:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError(f"Failed to parse client_id as a ClientIdentification, {e}")

        self.vmp = FileHashes()
        if self.client_id.vmp_data:
            try:
                self.vmp.ParseFromString(self.client_id.vmp_data)
                if self.vmp.SerializeToString() != self.client_id.vmp_data:
                    raise DecodeError("partial parse")
            except DecodeError as e:
                raise DecodeError(f"Failed to parse Client ID's VMP data as a FileHashes, {e}")

        signed_drm_certificate = SignedDrmCertificate()
        drm_certificate = DrmCertificate()

        try:
            signed_drm_certificate.ParseFromString(self.client_id.token)
            if signed_drm_certificate.SerializeToString() != self.client_id.token:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError(f"Failed to parse the Signed DRM Certificate of the Client ID, {e}")

        try:
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)
            if drm_certificate.SerializeToString() != signed_drm_certificate.drm_certificate:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError(f"Failed to parse the DRM Certificate of the Client ID, {e}")

        self.system_id = drm_certificate.system_id

    def __repr__(self) -> str:
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join([f"{k}={repr(v)}" for k, v in self.__dict__.items()])
        )

    @classmethod
    def loads(cls, data: Union[bytes, str]) -> Device:
        if isinstance(data, str):
            data = base64.b64decode(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Expecting Bytes or Base64 input, got {data!r}")
        return cls(**cls.supported_structure.parse(data))

    @staticmethod
    def _metadata_from_file_inputs(*values: Any) -> tuple[Optional[DeviceTypes], Optional[int]]:
        directories = []
        for value in values:
            if value in (None, False) or isinstance(value, bytes):
                continue
            try:
                path = Path(value)
            except TypeError:
                continue
            parent = path if path.is_dir() else path.parent
            if parent not in directories:
                directories.append(parent)
        resolved_type = None
        resolved_level = None
        for directory in directories:
            metadata_path = directory / "wv.json"
            if not metadata_path.is_file():
                continue
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            level = metadata.get("security_level")
            if resolved_level is None:
                try:
                    level = int(level)
                    if level in (1, 2, 3):
                        resolved_level = level
                except (TypeError, ValueError):
                    pass
            session_type = str(metadata.get("session_id_type", "")).strip().upper()
            if resolved_type is None and session_type in DeviceTypes.__members__:
                resolved_type = DeviceTypes[session_type]
        if resolved_level is None:
            for directory in directories:
                candidates = [directory.name]
                for value in values:
                    if value in (None, False) or isinstance(value, bytes):
                        continue
                    try:
                        path = Path(value)
                    except TypeError:
                        continue
                    if path.parent == directory:
                        candidates.append(path.name)
                for candidate in candidates:
                    match = re.search(r"(?:^|[_\-.])l([123])(?:$|[_\-.])", candidate, flags=re.IGNORECASE)
                    if match:
                        resolved_level = int(match.group(1))
                        break
                if resolved_level is not None:
                    break
        return resolved_type, resolved_level

    @staticmethod
    def _resolve_device_type(value: Optional[Union[DeviceTypes, str]], fallback: Optional[DeviceTypes]) -> DeviceTypes:
        if value is None:
            return fallback or DeviceTypes.ANDROID
        if isinstance(value, DeviceTypes):
            return value
        normalized = str(value).strip().upper()
        if normalized not in DeviceTypes.__members__:
            valid = ", ".join(DeviceTypes.__members__)
            raise ValueError(f"Invalid device type '{value}'. Expected one of: {valid}")
        return DeviceTypes[normalized]

    @classmethod
    def from_files(
        cls,
        private_key: Optional[Union[Path, str, bytes]] = None,
        client_id: Optional[Union[Path, str, bytes]] = None,
        vmp: Union[Path, str, bytes, bool, None] = False,
        type_: Optional[Union[DeviceTypes, str]] = None,
        security_level: Optional[int] = None,
        flags: Optional[dict] = None,
        certificate: Optional[Union[Path, str, bytes]] = None,
        key: Optional[Union[Path, str, bytes]] = None
    ) -> Device:
        selected_private_key = key if key is not None else private_key
        selected_client_id = certificate if certificate is not None else client_id
        if selected_private_key is None:
            raise ValueError("Device private key path or bytes are required.")
        if selected_client_id is None:
            raise ValueError("Device client certificate path or bytes are required.")
        inferred_type, inferred_level = cls._metadata_from_file_inputs(selected_private_key, selected_client_id, vmp)
        resolved_type = cls._resolve_device_type(type_, inferred_type)
        if security_level is None:
            resolved_level = inferred_level if inferred_level is not None else 3
        else:
            resolved_level = int(security_level)
        if resolved_level not in (1, 2, 3):
            raise ValueError(f"Invalid security level: {resolved_level}. Expected 1, 2, or 3.")
        private_key_bytes = selected_private_key if isinstance(selected_private_key, bytes) else Path(selected_private_key).read_bytes()
        client_id_bytes = selected_client_id if isinstance(selected_client_id, bytes) else Path(selected_client_id).read_bytes()
        device = cls(
            type_=resolved_type,
            security_level=resolved_level,
            flags=flags,
            private_key=private_key_bytes,
            client_id=client_id_bytes
        )
        if vmp:
            vmp_bytes = vmp if isinstance(vmp, bytes) else Path(vmp).read_bytes()
            parsed_vmp = FileHashes()
            try:
                parsed_vmp.ParseFromString(vmp_bytes)
                if parsed_vmp.SerializeToString() != vmp_bytes:
                    raise DecodeError("partial parse")
            except DecodeError as e:
                raise DecodeError(f"Failed to parse VMP data as FileHashes, {e}")
            device.client_id.vmp_data = vmp_bytes
            device.vmp = parsed_vmp
        return device

    @classmethod
    def load_from_files(cls, private_key: Union[Path, str, bytes], client_id: Union[Path, str, bytes], vmp: Union[Path, str, bytes, bool, None] = False, type: Optional[Union[DeviceTypes, str]] = None, type_: Optional[Union[DeviceTypes, str]] = None, security_level: Optional[int] = None, flags: Optional[dict] = None) -> Device:
        selected_type = type_ if type_ is not None else type
        return cls.from_files(
            private_key=private_key,
            client_id=client_id,
            vmp=vmp,
            type_=selected_type,
            security_level=security_level,
            flags=flags
        )

    @classmethod
    def from_directory(cls, path: Union[Path, str], type_: Optional[Union[DeviceTypes, str]] = None, security_level: Optional[int] = None, flags: Optional[dict] = None) -> Device:
        directory = Path(path)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Device directory does not exist: {directory}")
        private_key_path = directory / "device_private_key"
        client_id_path = directory / "device_client_id_blob"
        vmp_path = directory / "device_vmp_blob"
        if not private_key_path.exists():
            raise FileNotFoundError(f"Missing device private key file: {private_key_path.name}")
        if not client_id_path.exists():
            raise FileNotFoundError(f"Missing device client ID blob file: {client_id_path.name}")
        return cls.from_files(
            private_key=private_key_path,
            client_id=client_id_path,
            vmp=vmp_path if vmp_path.exists() else False,
            type_=type_,
            security_level=security_level,
            flags=flags
        )

    @classmethod
    def load(cls, path: Union[Path, str]) -> Device:
        if not isinstance(path, (Path, str)):
            raise ValueError(f"Expecting Path object or path string, got {path!r}")
        path = Path(path)
        if path.is_dir():
            return cls.from_directory(path)
        with path.open(mode="rb") as f:
            return cls(**cls.supported_structure.parse_stream(f))

    def dumps(self) -> bytes:
        private_key = self.private_key.export_key("DER") if self.private_key else None
        return self.supported_structure.build(dict(
            version=2,
            type_=self.type.value,
            security_level=self.security_level,
            flags=self.flags,
            private_key_len=len(private_key) if private_key else 0,
            private_key=private_key,
            client_id_len=len(self.client_id.SerializeToString()) if self.client_id else 0,
            client_id=self.client_id.SerializeToString() if self.client_id else None
        ))

    def dump(self, path: Union[Path, str]) -> None:
        if not isinstance(path, (Path, str)):
            raise ValueError(f"Expecting Path object or path string, got {path!r}")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.dumps())

    @classmethod
    def migrate(cls, data: Union[bytes, str]) -> Device:
        if isinstance(data, str):
            data = base64.b64decode(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Expecting Bytes or Base64 input, got {data!r}")

        header = _Structures.header.parse(data)
        if header.version == 2:
            raise ValueError("Device Data is already migrated to the latest version.")
        if header.version == 0 or header.version > 2:
                                                                                                  
            raise ValueError("Device Data does not seem to be a WVD file (v0).")

        if header.version == 1:            
            v1_struct = _Structures.v1.parse(data)
            v1_struct.version = 2                                        
            v1_struct.flags = {}                                             

            vmp = FileHashes()
            if v1_struct.vmp:
                try:
                    vmp.ParseFromString(v1_struct.vmp)
                    if vmp.SerializeToString() != v1_struct.vmp:
                        raise DecodeError("partial parse")
                except DecodeError as e:
                    raise DecodeError(f"Failed to parse VMP data as FileHashes, {e}")
                v1_struct.vmp = vmp

                client_id = ClientIdentification()
                try:
                    client_id.ParseFromString(v1_struct.client_id)
                    if client_id.SerializeToString() != v1_struct.client_id:
                        raise DecodeError("partial parse")
                except DecodeError as e:
                    raise DecodeError(f"Failed to parse VMP data as FileHashes, {e}")

                new_vmp_data = v1_struct.vmp.SerializeToString()
                if client_id.vmp_data and client_id.vmp_data != new_vmp_data:
                    logging.getLogger("migrate").warning("Client ID already has Verified Media Path data")
                client_id.vmp_data = new_vmp_data
                v1_struct.client_id = client_id.SerializeToString()

            try:
                data = _Structures.v2.build(v1_struct)
            except (ValueError, TypeError) as e:
                raise ValueError(f"Migration failed, {e}")

        try:
            return cls.loads(data)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Device Data seems to be corrupt or invalid, or migration failed, {e}")


__all__ = ("Device", "DeviceTypes")


def _parse_pssh_box(data):
    data = bytes(data)
    if len(data) < 32:
        raise ValueError("PSSH box is too short.")
    size32 = int.from_bytes(data[:4], "big")
    if data[4:8] != b"pssh":
        raise ValueError("Input is not a PSSH box.")
    offset = 8
    if size32 == 1:
        if len(data) < 16:
            raise ValueError("Truncated large-size PSSH box.")
        box_size = int.from_bytes(data[8:16], "big")
        offset = 16
    elif size32 == 0:
        box_size = len(data)
    else:
        box_size = size32
    if box_size > len(data) or box_size < offset + 24:
        raise ValueError("Invalid PSSH box size.")
    version = data[offset]
    flags = int.from_bytes(data[offset + 1:offset + 4], "big")
    offset += 4
    if version not in (0, 1):
        raise ValueError(f"Unsupported PSSH version: {version}")
    system_id = UUID(bytes=data[offset:offset + 16])
    offset += 16
    key_ids = []
    if version == 1:
        if offset + 4 > box_size:
            raise ValueError("Truncated PSSH key count.")
        key_count = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        needed = key_count * 16
        if offset + needed > box_size:
            raise ValueError("Truncated PSSH key IDs.")
        key_ids = [UUID(bytes=data[i:i + 16]) for i in range(offset, offset + needed, 16)]
        offset += needed
    if offset + 4 > box_size:
        raise ValueError("Truncated PSSH init-data length.")
    init_size = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    end = offset + init_size
    if end > box_size:
        raise ValueError("Truncated PSSH init data.")
    if end != box_size:
        raise ValueError(f"Unexpected trailing data inside PSSH box: {box_size - end} bytes.")
    return {
        "version": version,
        "flags": flags,
        "system_ID": system_id,
        "key_IDs": key_ids,
        "init_data": data[offset:end],
    }


def _build_pssh_box(version, flags, system_id, key_ids, init_data):
    version = int(version)
    flags = int(flags)
    if version not in (0, 1):
        raise ValueError(f"Unsupported PSSH version: {version}")
    if not isinstance(system_id, UUID):
        system_id = UUID(str(system_id))
    init_data = bytes(init_data or b"")
    key_ids = list(key_ids or [])
    payload = bytearray()
    payload.append(version)
    payload.extend((flags & 0xFFFFFF).to_bytes(3, "big"))
    payload.extend(system_id.bytes)
    if version == 1:
        normalized = []
        for key_id in key_ids:
            normalized.append(key_id if isinstance(key_id, UUID) else UUID(str(key_id)))
        payload.extend(len(normalized).to_bytes(4, "big"))
        for key_id in normalized:
            payload.extend(key_id.bytes)
    payload.extend(len(init_data).to_bytes(4, "big"))
    payload.extend(init_data)
    size = 8 + len(payload)
    if size > 0xFFFFFFFF:
        raise ValueError("PSSH box is too large for a 32-bit MP4 box size.")
    return size.to_bytes(4, "big") + b"pssh" + bytes(payload)


class PSSH:
    class SystemId:
        Widevine = UUID(hex="edef8ba979d64acea3c827dcd51d21ed")

    def __init__(self, data: Union[dict, str, bytes], strict: bool = False):
        if not data:
            raise ValueError("Data must not be empty.")
        if isinstance(data, dict):
            box = data
        else:
            if isinstance(data, str):
                try:
                    data = base64.b64decode(data)
                except (binascii.Error, binascii.Incomplete) as e:
                    raise binascii.Error(f"Could not decode data as Base64, {e}")
            if not isinstance(data, bytes):
                raise TypeError(f"Expected bytes, base64, or a PSSH mapping, not {data!r}")
            try:
                box = _parse_pssh_box(data)
            except (ValueError, TypeError):
                try:
                    widevine_pssh_data = WidevinePsshData()
                    widevine_pssh_data.ParseFromString(data)
                    data_serialized = widevine_pssh_data.SerializeToString()
                    if data_serialized != data:
                        raise DecodeError("partial parse")
                    box = {
                        "version": 0,
                        "flags": 0,
                        "system_ID": PSSH.SystemId.Widevine,
                        "key_IDs": [],
                        "init_data": data_serialized,
                    }
                except DecodeError:
                    if strict:
                        raise DecodeError("Could not parse data as a PSSH box nor WidevinePsshData.")
                    box = {
                        "version": 0,
                        "flags": 0,
                        "system_ID": PSSH.SystemId.Widevine,
                        "key_IDs": [],
                        "init_data": data,
                    }
        self.version = int(box["version"])
        self.flags = int(box.get("flags", 0))
        self.system_id = box["system_ID"] if isinstance(box["system_ID"], UUID) else UUID(str(box["system_ID"]))
        self.__key_ids = list(box.get("key_IDs") or [])
        self.init_data = bytes(box.get("init_data") or b"")

    def __repr__(self) -> str:
        return f"PSSH<{self.system_id}>(v{self.version}; {self.flags}, {self.key_ids}, {self.init_data})"

    def __str__(self) -> str:
        return self.dumps()

    @classmethod
    def new(
        cls,
        system_id: UUID,
        key_ids: Optional[list[Union[UUID, str, bytes]]] = None,
        init_data: Optional[Union[WidevinePsshData, str, bytes]] = None,
        version: int = 0,
        flags: int = 0
    ) -> PSSH:
        if not system_id:
            raise ValueError("A System ID must be specified.")
        if not isinstance(system_id, UUID):
            raise TypeError(f"Expected system_id to be a UUID, not {system_id!r}")
        if key_ids is not None and not isinstance(key_ids, list):
            raise TypeError(f"Expected key_ids to be a list not {key_ids!r}")
        if init_data is not None and not isinstance(init_data, (WidevinePsshData, str, bytes)):
            raise TypeError(f"Expected init_data to be WidevinePsshData, base64, hex, or bytes, not {init_data!r}")
        if not isinstance(version, int) or version not in (0, 1):
            raise ValueError(f"Invalid version, must be either 0 or 1, not {version}.")
        if not isinstance(flags, int) or flags < 0:
            raise ValueError("Invalid flags.")
        if version == 0 and key_ids is not None and init_data is not None:
            raise ValueError("Version 0 PSSH boxes must use only init_data, not init_data and key_ids.")
        if version == 1 and init_data is None and key_ids is None:
            raise ValueError("Version 1 PSSH boxes must use either init_data or key_ids.")
        if init_data is not None:
            if isinstance(init_data, WidevinePsshData):
                init_data = init_data.SerializeToString()
            elif isinstance(init_data, str):
                if all(c in string.hexdigits for c in init_data):
                    init_data = bytes.fromhex(init_data)
                else:
                    init_data = base64.b64decode(init_data)
        else:
            init_data = b""
        pssh = cls(_build_pssh_box(version, flags, system_id, [], init_data))
        if key_ids:
            pssh.version = version
            pssh.set_key_ids(key_ids)
        return pssh

    @property
    def key_ids(self) -> list[UUID]:
        if self.version == 1 and self.__key_ids:
            return self.__key_ids
        if self.system_id == PSSH.SystemId.Widevine:
            cenc_header = WidevinePsshData()
            cenc_header.ParseFromString(self.init_data)
            return [
                UUID(bytes=key_id) if len(key_id) == 16 else
                UUID(hex=key_id.decode()) if len(key_id) == 32 else
                UUID(int=int.from_bytes(key_id, "big"))
                for key_id in cenc_header.key_ids
            ]
        raise ValueError(f"This PSSH is not supported by key_ids() property, {self.dumps()}")

    def dump(self) -> bytes:
        return _build_pssh_box(
            self.version,
            self.flags,
            self.system_id,
            self.__key_ids if self.version == 1 else [],
            self.init_data,
        )

    def dumps(self) -> str:
        return base64.b64encode(self.dump()).decode()

    def set_key_ids(self, key_ids: list[Union[UUID, str, bytes]]) -> None:
        if self.system_id != PSSH.SystemId.Widevine:
            raise ValueError(f"Only Widevine PSSH Boxes are supported, not {self.system_id}.")
        key_id_uuids = self.parse_key_ids(key_ids)
        if self.version == 1 or self.__key_ids:
            self.__key_ids = key_id_uuids
        cenc_header = WidevinePsshData()
        cenc_header.ParseFromString(self.init_data)
        cenc_header.key_ids[:] = [key_id.bytes for key_id in key_id_uuids]
        self.init_data = cenc_header.SerializeToString()

    @staticmethod
    def parse_key_ids(key_ids: list[Union[UUID, str, bytes]]) -> list[UUID]:
        if not isinstance(key_ids, list):
            raise TypeError(f"Expected key_ids to be a list, not {key_ids!r}")
        if not all(isinstance(x, (UUID, str, bytes)) for x in key_ids):
            raise TypeError("Some items of key_ids are not a UUID, str, or bytes.")
        uuids = []
        for key_id in key_ids:
            if isinstance(key_id, UUID):
                uuids.append(key_id)
                continue
            if isinstance(key_id, bytes):
                raw = key_id
            elif all(c in string.hexdigits for c in key_id):
                raw = bytes.fromhex(key_id)
            else:
                raw = base64.b64decode(key_id)
            if len(raw) != 16:
                raise ValueError(f"Key ID must be exactly 16 bytes, got {len(raw)}")
            uuids.append(UUID(bytes=raw))
        return uuids

__all__ = ("PSSH",)

def get_binary_path(*names: str) -> Optional[Path]:
    for name in names:
        path = shutil.which(name)
        if path:
            return Path(path)
    return None


class Cdm:
    uuid = UUID(bytes=b"\xed\xef\x8b\xa9\x79\xd6\x4a\xce\xa3\xc8\x27\xdc\xd5\x1d\x21\xed")
    urn = f"urn:uuid:{uuid}"
    key_format = urn
    service_certificate_challenge = b"\x08\x04"
    common_privacy_cert = (                                                                            
        "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEE"
        "Qa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3r"
        "M3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ"
        "7c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmlu"
        "ZS5jb20SgAOuNHMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M4PxL/C"
        "CpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnSq8x2"
        "/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeF"
        "Hd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98"
        "X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ=")
    staging_privacy_cert = (
        "CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhErjQXQI/zF2V4sJRwcZJtBd82NK+7zVbsGdD3mYePSq8"
        "MYK3mUbVX9wI3+lUB4FemmJ0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKqFxxPZmMNPkxgJxiJf14e+baq9a1Nuip+"
        "FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7tzY8U1nWpGYD5LKfdxkagatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2fz"
        "PvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQoJk87wFgRwMzTDY4E5SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUu"
        "Y29tEoADmD4wNSZ19AunFfwkm9rl1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeEjMdT/0l7ARp9qXeIoA4qprhM19"
        "ccB6SOv2FgLMpaPzIDCnKVww2pFbkdwYubyVk7jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lexjOY9Dv"
        "1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s+Cdkxd2b9yfvvpyGH4aTIfat4YkF9Nkvmm2mU224R1hx0WjocL"
        "sjA89wxul4TJPS3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3Tq26/LfGcF96njtvOUA4P5xRFtICogySKe6W"
        "nCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8ABHg9bOOTimO0sswHrRWSWX1XF15dXolCk65yEqz5lOfa2/fVomeopkU")
    root_signed_cert = SignedDrmCertificate()
    root_signed_cert.ParseFromString(base64.b64decode(
        "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZy"
        "f7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfM"
        "qIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx"
        "+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg1"
        "7B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSC"
        "UNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0a"
        "y5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZV"
        "dA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2F"
        "RXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7"
        "evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
    ))
    root_cert = DrmCertificate()
    root_cert.ParseFromString(root_signed_cert.drm_certificate)

    MAX_NUM_OF_SESSIONS = 16

    def __init__(
        self,
        device_type: Union[DeviceTypes, str],
        system_id: int,
        security_level: int,
        client_id: ClientIdentification,
        rsa_key: RSA.RsaKey
    ):
        """Initialize a Widevine Content Decryption Module (CDM)."""
        if not device_type:
            raise ValueError("Device Type must be provided")
        if isinstance(device_type, str):
            device_type = DeviceTypes[device_type]
        if not isinstance(device_type, DeviceTypes):
            raise TypeError(f"Expected device_type to be a {DeviceTypes!r} not {device_type!r}")

        if not system_id:
            raise ValueError("System ID must be provided")
        if not isinstance(system_id, int):
            raise TypeError(f"Expected system_id to be a {int} not {system_id!r}")

        if not security_level:
            raise ValueError("Security Level must be provided")
        if not isinstance(security_level, int):
            raise TypeError(f"Expected security_level to be a {int} not {security_level!r}")

        if not client_id:
            raise ValueError("Client ID must be provided")
        if not isinstance(client_id, ClientIdentification):
            raise TypeError(f"Expected client_id to be a {ClientIdentification} not {client_id!r}")

        if not rsa_key:
            raise ValueError("RSA Key must be provided")
        if not isinstance(rsa_key, RSA.RsaKey):
            raise TypeError(f"Expected rsa_key to be a {RSA.RsaKey} not {rsa_key!r}")

        self.device_type = device_type
        self.system_id = system_id
        self.security_level = security_level
        self.__client_id = client_id

        self.__signer = pss.new(rsa_key)
        self.__decrypter = PKCS1_OAEP.new(rsa_key)

        self.__sessions: dict[bytes, Session] = {}

    @classmethod
    def from_device(cls, device: Device) -> Cdm:
        return cls(
            device_type=device.type,
            system_id=device.system_id,
            security_level=device.security_level,
            client_id=device.client_id,
            rsa_key=device.private_key
        )

    def open(self) -> bytes:
        if len(self.__sessions) > self.MAX_NUM_OF_SESSIONS:
            raise TooManySessions(f"Too many Sessions open ({self.MAX_NUM_OF_SESSIONS}).")

        session = Session(len(self.__sessions) + 1)
        self.__sessions[session.id] = session

        return session.id

    def close(self, session_id: bytes) -> None:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")
        del self.__sessions[session_id]

    def set_service_certificate(self, session_id: bytes, certificate: Optional[Union[bytes, str]]) -> Optional[str]:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if certificate is None:
            if session.service_certificate:
                drm_certificate = DrmCertificate()
                drm_certificate.ParseFromString(session.service_certificate.drm_certificate)
                provider_id = drm_certificate.provider_id
            else:
                provider_id = None
            session.service_certificate = None
            return provider_id

        if isinstance(certificate, str):
            try:
                certificate = base64.b64decode(certificate)                   
            except binascii.Error:
                raise DecodeError("Could not decode certificate string as Base64, expected bytes.")
        elif not isinstance(certificate, bytes):
            raise DecodeError(f"Expecting Certificate to be bytes, not {certificate!r}")

        signed_message = SignedMessage()
        signed_drm_certificate = SignedDrmCertificate()
        drm_certificate = DrmCertificate()

        try:
            signed_message.ParseFromString(certificate)
            if all(
                                                                       
                bytes(chunk) == signed_message.SerializeToString()
                for chunk in zip(*[iter(certificate)] * len(signed_message.SerializeToString()))
            ):
                signed_drm_certificate.ParseFromString(signed_message.msg)
            else:
                signed_drm_certificate.ParseFromString(certificate)
                if signed_drm_certificate.SerializeToString() != certificate:
                    raise DecodeError("partial parse")
        except DecodeError as e:
                                                                                
            raise DecodeError(f"Could not parse certificate as a SignedDrmCertificate, {e}")

        try:
            pss. \
                new(RSA.import_key(self.root_cert.public_key)). \
                verify(
                    msg_hash=SHA1.new(signed_drm_certificate.drm_certificate),
                    signature=signed_drm_certificate.signature
                )
        except (ValueError, TypeError):
            raise SignatureMismatch("Signature Mismatch on SignedDrmCertificate, rejecting certificate")

        try:
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)
            if drm_certificate.SerializeToString() != signed_drm_certificate.drm_certificate:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError(f"Could not parse signed certificate's message as a DrmCertificate, {e}")

                                                                                                  
                                                                                                   
        session.service_certificate = signed_drm_certificate
        return drm_certificate.provider_id

    def get_service_certificate(self, session_id: bytes) -> Optional[SignedDrmCertificate]:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        return session.service_certificate

    def get_license_challenge(
        self,
        session_id: bytes,
        pssh: PSSH,
        license_type: str = "STREAMING",
        privacy_mode: bool = True
    ) -> bytes:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if not pssh:
            raise InvalidInitData("A pssh must be provided.")
        if not isinstance(pssh, PSSH):
            raise InvalidInitData(f"Expected pssh to be a {PSSH}, not {pssh!r}")

        if not isinstance(license_type, str):
            raise InvalidLicenseType(f"Expected license_type to be a {str}, not {license_type!r}")
        license_types = _license_type_enum()
        if license_type not in license_types.keys():
            raise InvalidLicenseType(
                f"Invalid license_type value of '{license_type}'. "
                f"Available values: {license_types.keys()}"
            )

        if self.device_type == DeviceTypes.ANDROID:                                            
            request_id = (get_random_bytes(4) + (b"\x00" * 4))       
            request_id += session.number.to_bytes(8, "little")                                                                
            request_id = request_id.hex().upper().encode()
        else:
            request_id = get_random_bytes(16)

        license_request = LicenseRequest(
            client_id=(
                self.__client_id
            ) if not (session.service_certificate and privacy_mode) else None,
            encrypted_client_id=self.encrypt_client_id(
                client_id=self.__client_id,
                service_certificate=session.service_certificate
            ) if session.service_certificate and privacy_mode else None,
            content_id=LicenseRequest.ContentIdentification(
                widevine_pssh_data=LicenseRequest.ContentIdentification.WidevinePsshData(
                    pssh_data=[pssh.init_data],                                              
                    license_type=license_type,
                    request_id=request_id
                )
            ),
            type="NEW",
            request_time=int(time.time()),
            protocol_version="VERSION_2_1",
            key_control_nonce=random.randrange(1, 2 ** 31),
        ).SerializeToString()

        signed_license_request = SignedMessage(
            type="LICENSE_REQUEST",
            msg=license_request,
            signature=self.__signer.sign(SHA1.new(license_request))
        ).SerializeToString()

        session.context[request_id] = self.derive_context(license_request)

        return signed_license_request

    def parse_license(self, session_id: bytes, license_message: Union[SignedMessage, bytes, str]) -> None:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if not license_message:
            raise InvalidLicenseMessage("Cannot parse an empty license_message")

        if isinstance(license_message, str):
            try:
                license_message = base64.b64decode(license_message)
            except (binascii.Error, binascii.Incomplete) as e:
                raise InvalidLicenseMessage(f"Could not decode license_message as Base64, {e}")

        if isinstance(license_message, bytes):
            signed_message = SignedMessage()
            try:
                signed_message.ParseFromString(license_message)
                if signed_message.SerializeToString() != license_message:
                    raise DecodeError(license_message)
            except DecodeError as e:
                raise InvalidLicenseMessage(f"Could not parse license_message as a SignedMessage, {e}")
            license_message = signed_message

        if not isinstance(license_message, SignedMessage):
            raise InvalidLicenseMessage(f"Expecting license_response to be a SignedMessage, got {license_message!r}")

        if license_message.type != SignedMessage.MessageType.Value("LICENSE"):
            raise InvalidLicenseMessage(
                f"Expecting a LICENSE message, not a "
                f"'{SignedMessage.MessageType.Name(license_message.type)}' message."
            )

        licence = License()
        licence.ParseFromString(license_message.msg)

        context = session.context.get(licence.id.request_id)
        if not context:
            raise InvalidContext("Cannot parse a license message without first making a license request")

        enc_key, mac_key_server, _ = self.derive_keys(
            *context,
            key=self.__decrypter.decrypt(license_message.session_key)
        )
        computed_signature = HMAC. \
            new(mac_key_server, digestmod=SHA256). \
            update(license_message.oemcrypto_core_message or b""). \
            update(license_message.msg). \
            digest()

        if license_message.signature != computed_signature:
            raise SignatureMismatch("Signature Mismatch on License Message, rejecting license")

        session.keys = [
            Key.from_key_container(key, enc_key)
            for key in licence.key
        ]

        del session.context[licence.id.request_id]

    def get_keys(self, session_id: bytes, type_: Optional[Union[int, str]] = None) -> list[Key]:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        try:
            if isinstance(type_, str):
                type_ = License.KeyContainer.KeyType.Value(type_)
            elif isinstance(type_, int):
                License.KeyContainer.KeyType.Name(type_)             
            elif type_ is not None:
                raise TypeError(f"Expected type_ to be a {License.KeyContainer.KeyType} or int, not {type_!r}")
        except ValueError as e:
            raise ValueError(f"Could not parse type_ as a {License.KeyContainer.KeyType}, {e}")

        return [
            key
            for key in session.keys
            if not type_ or key.type == License.KeyContainer.KeyType.Name(type_)
        ]

    def decrypt(
        self,
        session_id: bytes,
        input_file: Union[Path, str],
        output_file: Union[Path, str],
        temp_dir: Optional[Union[Path, str]] = None,
        exists_ok: bool = False
    ) -> int:
        if not input_file:
            raise ValueError("Cannot decrypt nothing, specify an input path")
        if not output_file:
            raise ValueError("Cannot decrypt nowhere, specify an output path")

        if not isinstance(input_file, (Path, str)):
            raise ValueError(f"Expecting input_file to be a Path or str, got {input_file!r}")
        if not isinstance(output_file, (Path, str)):
            raise ValueError(f"Expecting output_file to be a Path or str, got {output_file!r}")
        if not isinstance(temp_dir, (Path, str)) and temp_dir is not None:
            raise ValueError(f"Expecting temp_dir to be a Path or str, got {temp_dir!r}")

        input_file = Path(input_file)
        output_file = Path(output_file)
        temp_dir_ = Path(temp_dir) if temp_dir else None

        if not input_file.is_file():
            raise FileNotFoundError(f"Input file does not exist: {Path(input_file).name}")
        if output_file.is_file() and not exists_ok:
            raise FileExistsError(f"Output file already exists: {Path(output_file).name}")

        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if not session.keys:
            raise NoKeysLoaded("No Keys are loaded yet, cannot decrypt")

        platform = {"win32": "win", "darwin": "osx"}.get(sys.platform, sys.platform)
        executable = get_binary_path("shaka-packager", f"packager-{platform}", f"packager-{platform}-x64")
        if not executable:
            raise EnvironmentError("Shaka Packager executable not found but is required")

        args = [
            f"input={input_file},stream=0,output={output_file}",
            "--enable_raw_key_decryption",
            "--keys", ",".join([
                label
                for i, key in enumerate(session.keys)
                for label in [
                    f"label=1_{i}:key_id={key.kid.hex}:key={key.key.hex()}",
                                                                         
                    f"label=2_{i}:key_id={'0' * 32}:key={key.key.hex()}"
                ]
                if key.type == "CONTENT"
            ])
        ]

        if temp_dir_:
            temp_dir_.mkdir(parents=True, exist_ok=True)
            args.extend(["--temp_dir", str(temp_dir_)])

        return subprocess.check_call([executable, *args])

    @staticmethod
    def encrypt_client_id(
        client_id: ClientIdentification,
        service_certificate: Union[SignedDrmCertificate, DrmCertificate],
        key: Optional[bytes] = None,
        iv: Optional[bytes] = None
    ) -> EncryptedClientIdentification:
        """Encrypt the Client ID with the Service's Privacy Certificate."""
        privacy_key = key or get_random_bytes(16)
        privacy_iv = iv or get_random_bytes(16)

        if isinstance(service_certificate, SignedDrmCertificate):
            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(service_certificate.drm_certificate)
            service_certificate = drm_certificate
        if not isinstance(service_certificate, DrmCertificate):
            raise ValueError(f"Expecting Service Certificate to be a DrmCertificate, not {service_certificate!r}")

        encrypted_client_id = EncryptedClientIdentification(
            provider_id=service_certificate.provider_id,
            service_certificate_serial_number=service_certificate.serial_number,
            encrypted_client_id=AES.
            new(privacy_key, AES.MODE_CBC, privacy_iv).
            encrypt(CryptoPadding.pad(client_id.SerializeToString(), 16)),
            encrypted_client_id_iv=privacy_iv,
            encrypted_privacy_key=PKCS1_OAEP.
            new(RSA.importKey(service_certificate.public_key)).
            encrypt(privacy_key)
        )

        return encrypted_client_id

    @staticmethod
    def derive_context(message: bytes) -> tuple[bytes, bytes]:
        """Returns 2 Context Data used for computing the AES Encryption and HMAC Keys."""

        def _get_enc_context(msg: bytes) -> bytes:
            label = b"ENCRYPTION"
            key_size = 16 * 8           
            return label + b"\x00" + msg + key_size.to_bytes(4, "big")

        def _get_mac_context(msg: bytes) -> bytes:
            label = b"AUTHENTICATION"
            key_size = 32 * 8 * 2           
            return label + b"\x00" + msg + key_size.to_bytes(4, "big")

        return _get_enc_context(message), _get_mac_context(message)

    @staticmethod
    def derive_keys(enc_context: bytes, mac_context: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:

        def _derive(session_key: bytes, context: bytes, counter: int) -> bytes:
            return CMAC. \
                new(session_key, ciphermod=AES). \
                update(counter.to_bytes(1, "big") + context). \
                digest()

        enc_key = _derive(key, enc_context, 1)
        mac_key_server = _derive(key, mac_context, 1)
        mac_key_server += _derive(key, mac_context, 2)
        mac_key_client = _derive(key, mac_context, 3)
        mac_key_client += _derive(key, mac_context, 4)
        return enc_key, mac_key_server, mac_key_client


__all__ = ("Cdm",)

def read_binary_argument(value: str) -> bytes:
    path = Path(value)
    if path.exists():
        return path.read_bytes()
    cleaned = value.strip()
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        pass
    try:
        return base64.b64decode(cleaned)
    except binascii.Error as error:
        raise ValueError(f"Input is not a valid path, hex value, or Base64 value: {value}") from error

def parse_headers(values: Optional[list[str]]) -> dict[str, str]:
    headers = {}
    for item in values or []:
        if ":" not in item:
            raise ValueError(f"Invalid header value: {item}. Expected format: Name: Value")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip().strip('"')
    return headers

def build_device_from_args(args: argparse.Namespace) -> Device:
    if getattr(args, "wvd", None):
        return Device.load(args.wvd)
    if getattr(args, "device_dir", None):
        return Device.from_directory(
            path=args.device_dir,
            type_=normalize_device_type(args.type),
            security_level=args.level,
            flags=None
        )
    if getattr(args, "key", None) and getattr(args, "client_id", None):
        return Device.from_files(
            private_key=args.key,
            client_id=args.client_id,
            vmp=getattr(args, "vmp", None),
            type_=normalize_device_type(args.type),
            security_level=args.level,
            flags=None
        )
    raise ValueError("Provide a WVD file, a device directory, or both a private key file and a client ID blob file.")


def short_path(value: Any) -> Any:
    if value in (None, False):
        return value
    if isinstance(value, (str, Path)):
        return Path(value).name
    return value


def emit_json(data: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def emit_line(message: str) -> None:
    sys.stdout.write(message + "\n")


def command_info(args: argparse.Namespace) -> int:
    device = build_device_from_args(args)
    client_info = {entry.name: entry.value for entry in device.client_id.client_info}
    capabilities = {}
    try:
        capabilities = _message_to_dict(device.client_id).get("client_capabilities", {})
    except Exception:
        capabilities = {}
    result = {
        "input": {
            "wvd": short_path(getattr(args, "wvd", None)),
            "device_dir": short_path(getattr(args, "device_dir", None)),
            "key": short_path(getattr(args, "key", None)),
            "client_id": short_path(getattr(args, "client_id", None)),
            "vmp": short_path(getattr(args, "vmp", None))
        },
        "device": {
            "type": device.type.name,
            "system_id": device.system_id,
            "security_level": device.security_level,
            "has_vmp": bool(device.client_id.vmp_data)
        },
        "client_info": client_info,
        "client_capabilities": capabilities
    }
    emit_json(result)
    return 0


def normalize_device_type(value: Union[str, DeviceTypes]) -> DeviceTypes:
    if isinstance(value, DeviceTypes):
        return value
    if not isinstance(value, str):
        raise ValueError(f"Invalid device type: {value!r}")
    normalized = value.strip().upper()
    if normalized not in DeviceTypes.__members__:
        valid = ", ".join(DeviceTypes.__members__)
        raise ValueError(f"Invalid device type '{value}'. Expected one of: {valid}")
    return DeviceTypes[normalized]


def build_wvd_name(device: Device, data: bytes) -> str:
    client_info = {entry.name: entry.value for entry in device.client_id.client_info}
    company = client_info.get("company_name") or client_info.get("manufacturer") or client_info.get("vendor") or "unknown"
    model = client_info.get("model_name") or client_info.get("model") or client_info.get("device_name") or "device"
    name = f"{company} {model}"
    if client_info.get("widevine_cdm_version"):
        name += f" {client_info['widevine_cdm_version']}"
    name += f" {crc32(data).to_bytes(4, 'big').hex()}"
    name = unicodedata.normalize("NFKD", name.strip().lower().replace(" ", "_"))
    name = name.encode("ascii", "ignore").decode("ascii")
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("._-")
    return f"{name}_{device.system_id}_l{device.security_level}.wvd"


def command_create_wvd(args: argparse.Namespace) -> int:
    device_type = normalize_device_type(args.type)
    if getattr(args, "device_dir", None):
        device = Device.from_directory(path=args.device_dir, type_=device_type, security_level=args.level, flags=None)
    else:
        if not args.key:
            raise ValueError("A private key file is required when --device-dir is not used.")
        if not args.client_id:
            raise ValueError("A client ID blob file is required when --device-dir is not used.")
        device = Device.from_files(certificate=args.client_id, key=args.key, vmp=args.vmp if args.vmp else False, type_=device_type, security_level=args.level, flags=None)
    wvd_data = device.dumps()
    if args.output:
        output = Path(args.output)
        if output.suffix:
            if output.suffix.lower() != ".wvd":
                logging.getLogger("create-wvd").warning("Saving WVD with extension '%s', but '.wvd' is recommended.", output.suffix)
            output_path = output
        else:
            output_path = output / build_wvd_name(device, wvd_data)
    else:
        output_path = Path.cwd() / build_wvd_name(device, wvd_data)
    if output_path.exists() and not args.overwrite:
        raise FileExistsError(f"Output already exists: {output_path.name}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(wvd_data)
    emit_json({"status": "created", "file": output_path.name, "device": {"type": device.type.name, "system_id": device.system_id, "security_level": device.security_level}})
    return 0


def find_single_wvd_in_current_directory() -> Path:
    candidates = sorted(Path.cwd().glob("*.wvd"))
    if not candidates:
        raise FileNotFoundError("No WVD file was provided and no .wvd file was found in the current directory.")
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        raise ValueError(f"No WVD file was provided and multiple .wvd files were found: {names}")
    return candidates[0]


def write_metadata_file(path: Path, device: Device) -> None:
    client_info = {entry.name: entry.value for entry in device.client_id.client_info}
    capabilities = {}
    try:
        capabilities = _message_to_dict(device.client_id).get("client_capabilities", {})
    except Exception:
        capabilities = {}
    lines = ["wvd:", f"  device_type: {device.type.name}", f"  security_level: {device.security_level}", "client_info:"]
    for key, value in client_info.items():
        safe_value = str(value).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'  {key}: "{safe_value}"')
    lines.append("capabilities:")
    if capabilities:
        for key, value in capabilities.items():
            safe_value = str(value).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'  {key}: "{safe_value}"')
    else:
        lines.append("  {}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def command_export_wvd(args: argparse.Namespace) -> int:
    input_path = Path(args.input) if args.input else find_single_wvd_in_current_directory()
    if not input_path.is_file():
        raise FileNotFoundError(f"WVD file does not exist: {input_path.name}")
    device = Device.load(input_path)
    output_root = Path(args.output) if args.output else Path.cwd()
    output = output_root / input_path.stem
    if output.exists():
        if any(output.iterdir()) and not args.overwrite:
            raise FileExistsError(f"Output directory is not empty: {output.name}")
    else:
        output.mkdir(parents=True, exist_ok=True)
    metadata_path = output / "metadata.yml"
    private_key_pem_path = output / "private_key.pem"
    private_key_der_path = output / "private_key.der"
    client_id_path = output / "client_id.bin"
    vmp_path = output / "vmp.bin"
    target_paths = [metadata_path, private_key_pem_path, private_key_der_path, client_id_path]
    if device.client_id.vmp_data:
        target_paths.append(vmp_path)
    for target in target_paths:
        if target.exists() and not args.overwrite:
            raise FileExistsError(f"Output already exists: {target.name}")
    write_metadata_file(metadata_path, device)
    private_key_pem_path.write_text(device.private_key.export_key().decode(), encoding="utf-8")
    private_key_der_path.write_bytes(device.private_key.export_key(format="DER"))
    client_id_path.write_bytes(device.client_id.SerializeToString())
    if device.client_id.vmp_data:
        vmp_path.write_bytes(device.client_id.vmp_data)
    exported_files = [metadata_path.name, private_key_pem_path.name, private_key_der_path.name, client_id_path.name]
    if device.client_id.vmp_data:
        exported_files.append(vmp_path.name)
    emit_json({"status": "exported", "source": input_path.name, "output_directory": output.name, "files": exported_files, "has_vmp": bool(device.client_id.vmp_data)})
    return 0


def command_migrate_wvd(args: argparse.Namespace) -> int:
    output = Path(args.output) if args.output else Path(args.input).with_suffix(".v2.wvd")
    if output.exists() and not args.overwrite:
        raise FileExistsError(f"Output already exists: {output.name}")
    device = Device.migrate(Path(args.input).read_bytes())
    device.dump(output)
    emit_json({"status": "migrated", "file": output.name})
    return 0


def command_license(args: argparse.Namespace) -> int:
    device = build_device_from_args(args)
    pssh = PSSH(args.pssh)
    cdm = Cdm.from_device(device)
    session_id = cdm.open()
    try:
        if args.privacy and args.service_certificate:
            cdm.set_service_certificate(session_id, read_binary_argument(args.service_certificate))
        challenge = cdm.get_license_challenge(session_id, pssh, args.license_type, privacy_mode=args.privacy)
        if args.challenge_output:
            Path(args.challenge_output).write_bytes(challenge)
        if args.print_challenge:
            emit_line(base64.b64encode(challenge).decode())
        if not args.server and not args.license_response:
            if not args.print_challenge:
                emit_line(base64.b64encode(challenge).decode())
            return 0
        if args.license_response:
            license_message = read_binary_argument(args.license_response)
        else:
            headers = {
                "User-Agent": "Player/1.6.0 (Linux;Android 14) AndroidXMedia3/1.4.1",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept": "*/*",
                "Connection": "keep-alive"
            }
            headers.update(parse_headers(args.header))
            response = requests.post(args.server, headers=headers, data=challenge)
            response.raise_for_status()
            license_message = response.content
        cdm.parse_license(session_id, license_message)
        for key in cdm.get_keys(session_id):
            if args.include_non_content or key.type == "CONTENT":
                emit_line(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")
    finally:
        cdm.close(session_id)
    return 0


def command_pssh(args: argparse.Namespace) -> int:
    pssh = PSSH(args.input)
    if args.set_key_id:
        pssh.set_key_ids([UUID(value) for value in args.set_key_id])
    if args.output == "base64":
        emit_line(pssh.dumps())
    elif args.output == "hex":
        emit_line(pssh.dump().hex())
    elif args.output == "json":
        data = {"system_id": str(pssh.system_id), "key_ids": [str(key_id) for key_id in pssh.key_ids], "init_data": pssh.init_data.hex() if isinstance(pssh.init_data, bytes) else str(pssh.init_data), "box": pssh.dump().hex()}
        emit_json(data)
    else:
        sys.stdout.buffer.write(pssh.dump())
    return 0


def command_license_cli(args: argparse.Namespace) -> int:
    args.wvd = args.device_path
    args.device_dir = None
    args.key = None
    args.client_id = None
    args.vmp = False
    args.level = 3
    args.header = []
    args.service_certificate = None
    args.challenge_output = None
    args.license_response = None
    args.print_challenge = False
    args.include_non_content = True
    args.license_type = args.license_type.upper()
    return command_license(args)


def command_test_cli(args: argparse.Namespace) -> int:
    args.device_path = args.device
    args.pssh = "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
    args.server = "https://cwip-shaka-proxy.appspot.com/no_auth"
    args.license_type = "STREAMING"
    return command_license_cli(args)


def command_create_device_cli(args: argparse.Namespace) -> int:
    args.device_dir = None
    args.output = args.output
    args.overwrite = False
    return command_create_wvd(args)


def command_export_device_cli(args: argparse.Namespace) -> int:
    args.input = args.wvd_path
    args.output = args.out_dir
    args.overwrite = False
    return command_export_wvd(args)


def command_migrate_cli(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    devices = sorted(path.glob("*.wvd")) if path.is_dir() else [path]
    migrated = 0
    for item in devices:
        try:
            device = Device.migrate(item.read_bytes())
            device.dump(item)
            emit_line(f"Migrated {item.name}")
            migrated += 1
        except ValueError as error:
            emit_line(f"Skipped {item.name}: {error}")
    emit_line(f"Migrated {migrated}/{len(devices)} devices")
    return 0


def command_serve_cli(args: argparse.Namespace) -> int:
    raise RuntimeError("The single-file build does not include the remote serve implementation.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pywv", description="Python Widevine CDM utility")
    parser.add_argument("-v", "--version", action="store_true", help="Print version information.")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable DEBUG level logs.")
    sub = parser.add_subparsers(dest="cmd")

    license_cmd = sub.add_parser("license", help="Make a license request")
    license_cmd.add_argument("device_path")
    license_cmd.add_argument("pssh")
    license_cmd.add_argument("server")
    license_cmd.add_argument("-t", "--type", dest="license_type", default="STREAMING", choices=_license_type_enum().keys(), help="License Type to Request.")
    license_cmd.add_argument("-p", "--privacy", action="store_true", help="Use Privacy Mode, off by default.")
    license_cmd.set_defaults(func=command_license_cli)

    test_cmd = sub.add_parser("test", help="Test the CDM with the default CWIP sample")
    test_cmd.add_argument("device")
    test_cmd.add_argument("-p", "--privacy", action="store_true", help="Use Privacy Mode, off by default.")
    test_cmd.set_defaults(func=command_test_cli)

    create = sub.add_parser("create-device", help="Create a Widevine Device (.wvd) file")
    create.add_argument("-t", "--type", required=True, choices=["ANDROID", "CHROME", "android", "chrome"], help="Device Type")
    create.add_argument("-l", "--level", type=int, required=True, choices=[1, 2, 3], help="Device Security Level")
    create.add_argument("-k", "--key", required=True, help="Device RSA Private Key in PEM or DER format")
    create.add_argument("-c", "--client_id", dest="client_id", required=True, help="Widevine ClientIdentification Blob file")
    create.add_argument("-v", "--vmp", default=None, help="Widevine FileHashes Blob file")
    create.add_argument("-o", "--output", default=None, help="Output Path or Directory")
    create.set_defaults(func=command_create_device_cli)

    export = sub.add_parser("export-device", help="Export a Widevine Device (.wvd) file")
    export.add_argument("wvd_path")
    export.add_argument("-o", "--out_dir", dest="out_dir", default=None, help="Output Directory")
    export.set_defaults(func=command_export_device_cli)

    migrate = sub.add_parser("migrate", help="Upgrade earlier WVD formats")
    migrate.add_argument("path")
    migrate.set_defaults(func=command_migrate_cli)

    serve = sub.add_parser("serve", help="Serve local CDM and Widevine Devices remotely", add_help=False)
    serve.add_argument("config_path")
    serve.add_argument("-h", "--host", default="127.0.0.1", help="Host to serve from.")
    serve.add_argument("-p", "--port", type=int, default=8786, help="Port to serve from.")
    serve.set_defaults(func=command_serve_cli)

    return parser

__all__ = ("PSSH", "Device", "DeviceTypes", "Cdm", "Key", "Session", "ClientIdentification", "DrmCertificate", "SignedDrmCertificate", "SignedMessage", "License", "LicenseRequest", "WidevinePsshData", "FileHashes", "EncryptedClientIdentification", "Exception", "TooManySessions", "InvalidSession", "InvalidInitData", "InvalidLicenseType", "InvalidLicenseMessage", "InvalidContext", "SignatureMismatch", "NoKeysLoaded")

if __name__ == "__main__":
    cli_parser = build_parser()
    cli_args = cli_parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if cli_args.debug else logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
    if cli_args.version:
        emit_line(__version__)
        raise SystemExit(0)
    if not cli_args.cmd:
        cli_parser.print_help()
        raise SystemExit(0)
    try:
        raise SystemExit(cli_args.func(cli_args))
    except Exception as error:
        logging.getLogger("main").error(str(error))
        raise SystemExit(1)
