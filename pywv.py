
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
from datetime import datetime
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Any, Optional, Union
from uuid import UUID
from zlib import crc32
from xml.etree.ElementTree import XML
import requests
from construct import BitStruct, Bytes, Const, ConstructError, Container
from construct import Enum as CEnum
from construct import Int8ub, Int16ub
from construct import Optional as COptional
from construct import Padded, Padding, Struct, this
import construct
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import CMAC, HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util import Padding as CryptoPadding
from google.protobuf.message import DecodeError
from google.protobuf.json_format import MessageToDict
from pymp4.parser import Box
try:
    from unidecode import unidecode
    from unidecode import UnidecodeError
except Exception:
    class UnidecodeError(Exception):
        pass
    def unidecode(value: str) -> str:
        return value

__version__ = "1.9.0"

from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
                                   
_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16license_protocol.proto\x12\x10license_protocol\"\xb2\x01\n\x15LicenseIdentification\x12\x12\n\nrequest_id\x18\x01 \x01(\x0c\x12\x12\n\nsession_id\x18\x02 \x01(\x0c\x12\x13\n\x0bpurchase_id\x18\x03 \x01(\x0c\x12+\n\x04type\x18\x04 \x01(\x0e\x32\x1d.license_protocol.LicenseType\x12\x0f\n\x07version\x18\x05 \x01(\x05\x12\x1e\n\x16provider_session_token\x18\x06 \x01(\x0c\"\xcc\x17\n\x07License\x12\x33\n\x02id\x18\x01 \x01(\x0b\x32\'.license_protocol.LicenseIdentification\x12\x30\n\x06policy\x18\x02 \x01(\x0b\x32 .license_protocol.License.Policy\x12\x33\n\x03key\x18\x03 \x03(\x0b\x32&.license_protocol.License.KeyContainer\x12\x1a\n\x12license_start_time\x18\x04 \x01(\x03\x12*\n\x1bremote_attestation_verified\x18\x05 \x01(\x08:\x05\x66\x61lse\x12\x1d\n\x15provider_client_token\x18\x06 \x01(\x0c\x12\x19\n\x11protection_scheme\x18\x07 \x01(\r\x12\x17\n\x0fsrm_requirement\x18\x08 \x01(\x0c\x12\x12\n\nsrm_update\x18\t \x01(\x0c\x12l\n\x1cplatform_verification_status\x18\n \x01(\x0e\x32,.license_protocol.PlatformVerificationStatus:\x18PLATFORM_NO_VERIFICATION\x12\x11\n\tgroup_ids\x18\x0b \x03(\x0c\x1a\xae\x04\n\x06Policy\x12\x17\n\x08\x63\x61n_play\x18\x01 \x01(\x08:\x05\x66\x61lse\x12\x1a\n\x0b\x63\x61n_persist\x18\x02 \x01(\x08:\x05\x66\x61lse\x12\x18\n\tcan_renew\x18\x03 \x01(\x08:\x05\x66\x61lse\x12\"\n\x17rental_duration_seconds\x18\x04 \x01(\x03:\x01\x30\x12$\n\x19playback_duration_seconds\x18\x05 \x01(\x03:\x01\x30\x12#\n\x18license_duration_seconds\x18\x06 \x01(\x03:\x01\x30\x12,\n!renewal_recovery_duration_seconds\x18\x07 \x01(\x03:\x01\x30\x12\x1a\n\x12renewal_server_url\x18\x08 \x01(\t\x12 \n\x15renewal_delay_seconds\x18\t \x01(\x03:\x01\x30\x12)\n\x1erenewal_retry_interval_seconds\x18\n \x01(\x03:\x01\x30\x12\x1f\n\x10renew_with_usage\x18\x0b \x01(\x08:\x05\x66\x61lse\x12\'\n\x18\x61lways_include_client_id\x18\x0c \x01(\x08:\x05\x66\x61lse\x12*\n\x1fplay_start_grace_period_seconds\x18\r \x01(\x03:\x01\x30\x12-\n\x1esoft_enforce_playback_duration\x18\x0e \x01(\x08:\x05\x66\x61lse\x12*\n\x1csoft_enforce_rental_duration\x18\x0f \x01(\x08:\x04true\x1a\xc3\x0f\n\x0cKeyContainer\x12\n\n\x02id\x18\x01 \x01(\x0c\x12\n\n\x02iv\x18\x02 \x01(\x0c\x12\x0b\n\x03key\x18\x03 \x01(\x0c\x12<\n\x04type\x18\x04 \x01(\x0e\x32..license_protocol.License.KeyContainer.KeyType\x12U\n\x05level\x18\x05 \x01(\x0e\x32\x34.license_protocol.License.KeyContainer.SecurityLevel:\x10SW_SECURE_CRYPTO\x12T\n\x13required_protection\x18\x06 \x01(\x0b\x32\x37.license_protocol.License.KeyContainer.OutputProtection\x12U\n\x14requested_protection\x18\x07 \x01(\x0b\x32\x37.license_protocol.License.KeyContainer.OutputProtection\x12\x46\n\x0bkey_control\x18\x08 \x01(\x0b\x32\x31.license_protocol.License.KeyContainer.KeyControl\x12n\n operator_session_key_permissions\x18\t \x01(\x0b\x32\x44.license_protocol.License.KeyContainer.OperatorSessionKeyPermissions\x12\x66\n\x1cvideo_resolution_constraints\x18\n \x03(\x0b\x32@.license_protocol.License.KeyContainer.VideoResolutionConstraint\x12(\n\x19\x61nti_rollback_usage_table\x18\x0b \x01(\x08:\x05\x66\x61lse\x12\x13\n\x0btrack_label\x18\x0c \x01(\t\x1a\x33\n\nKeyControl\x12\x19\n\x11key_control_block\x18\x01 \x01(\x0c\x12\n\n\x02iv\x18\x02 \x01(\x0c\x1a\xfb\x04\n\x10OutputProtection\x12U\n\x04hdcp\x18\x01 \x01(\x0e\x32<.license_protocol.License.KeyContainer.OutputProtection.HDCP:\tHDCP_NONE\x12[\n\ncgms_flags\x18\x02 \x01(\x0e\x32<.license_protocol.License.KeyContainer.OutputProtection.CGMS:\tCGMS_NONE\x12n\n\rhdcp_srm_rule\x18\x03 \x01(\x0e\x32\x43.license_protocol.License.KeyContainer.OutputProtection.HdcpSrmRule:\x12HDCP_SRM_RULE_NONE\x12$\n\x15\x64isable_analog_output\x18\x04 \x01(\x08:\x05\x66\x61lse\x12%\n\x16\x64isable_digital_output\x18\x05 \x01(\x08:\x05\x66\x61lse\"y\n\x04HDCP\x12\r\n\tHDCP_NONE\x10\x00\x12\x0b\n\x07HDCP_V1\x10\x01\x12\x0b\n\x07HDCP_V2\x10\x02\x12\r\n\tHDCP_V2_1\x10\x03\x12\r\n\tHDCP_V2_2\x10\x04\x12\r\n\tHDCP_V2_3\x10\x05\x12\x1b\n\x16HDCP_NO_DIGITAL_OUTPUT\x10\xff\x01\"C\n\x04\x43GMS\x12\r\n\tCGMS_NONE\x10*\x12\r\n\tCOPY_FREE\x10\x00\x12\r\n\tCOPY_ONCE\x10\x02\x12\x0e\n\nCOPY_NEVER\x10\x03\"6\n\x0bHdcpSrmRule\x12\x16\n\x12HDCP_SRM_RULE_NONE\x10\x00\x12\x0f\n\x0b\x43URRENT_SRM\x10\x01\x1a\xaf\x01\n\x19VideoResolutionConstraint\x12\x1d\n\x15min_resolution_pixels\x18\x01 \x01(\r\x12\x1d\n\x15max_resolution_pixels\x18\x02 \x01(\r\x12T\n\x13required_protection\x18\x03 \x01(\x0b\x32\x37.license_protocol.License.KeyContainer.OutputProtection\x1a\x9d\x01\n\x1dOperatorSessionKeyPermissions\x12\x1c\n\rallow_encrypt\x18\x01 \x01(\x08:\x05\x66\x61lse\x12\x1c\n\rallow_decrypt\x18\x02 \x01(\x08:\x05\x66\x61lse\x12\x19\n\nallow_sign\x18\x03 \x01(\x08:\x05\x66\x61lse\x12%\n\x16\x61llow_signature_verify\x18\x04 \x01(\x08:\x05\x66\x61lse\"l\n\x07KeyType\x12\x0b\n\x07SIGNING\x10\x01\x12\x0b\n\x07\x43ONTENT\x10\x02\x12\x0f\n\x0bKEY_CONTROL\x10\x03\x12\x14\n\x10OPERATOR_SESSION\x10\x04\x12\x0f\n\x0b\x45NTITLEMENT\x10\x05\x12\x0f\n\x0bOEM_CONTENT\x10\x06\"z\n\rSecurityLevel\x12\x14\n\x10SW_SECURE_CRYPTO\x10\x01\x12\x14\n\x10SW_SECURE_DECODE\x10\x02\x12\x14\n\x10HW_SECURE_CRYPTO\x10\x03\x12\x14\n\x10HW_SECURE_DECODE\x10\x04\x12\x11\n\rHW_SECURE_ALL\x10\x05\"\xa3\x0c\n\x0eLicenseRequest\x12\x39\n\tclient_id\x18\x01 \x01(\x0b\x32&.license_protocol.ClientIdentification\x12J\n\ncontent_id\x18\x02 \x01(\x0b\x32\x36.license_protocol.LicenseRequest.ContentIdentification\x12:\n\x04type\x18\x03 \x01(\x0e\x32,.license_protocol.LicenseRequest.RequestType\x12\x14\n\x0crequest_time\x18\x04 \x01(\x03\x12$\n\x1ckey_control_nonce_deprecated\x18\x05 \x01(\x0c\x12H\n\x10protocol_version\x18\x06 \x01(\x0e\x32!.license_protocol.ProtocolVersion:\x0bVERSION_2_0\x12\x19\n\x11key_control_nonce\x18\x07 \x01(\r\x12L\n\x13\x65ncrypted_client_id\x18\x08 \x01(\x0b\x32/.license_protocol.EncryptedClientIdentification\x1a\xac\x08\n\x15\x43ontentIdentification\x12\x65\n\x12widevine_pssh_data\x18\x01 \x01(\x0b\x32G.license_protocol.LicenseRequest.ContentIdentification.WidevinePsshDataH\x00\x12W\n\x0bwebm_key_id\x18\x02 \x01(\x0b\x32@.license_protocol.LicenseRequest.ContentIdentification.WebmKeyIdH\x00\x12\x62\n\x10\x65xisting_license\x18\x03 \x01(\x0b\x32\x46.license_protocol.LicenseRequest.ContentIdentification.ExistingLicenseH\x00\x12T\n\tinit_data\x18\x04 \x01(\x0b\x32?.license_protocol.LicenseRequest.ContentIdentification.InitDataH\x00\x1an\n\x10WidevinePsshData\x12\x11\n\tpssh_data\x18\x01 \x03(\x0c\x12\x33\n\x0clicense_type\x18\x02 \x01(\x0e\x32\x1d.license_protocol.LicenseType\x12\x12\n\nrequest_id\x18\x03 \x01(\x0c\x1a\x64\n\tWebmKeyId\x12\x0e\n\x06header\x18\x01 \x01(\x0c\x12\x33\n\x0clicense_type\x18\x02 \x01(\x0e\x32\x1d.license_protocol.LicenseType\x12\x12\n\nrequest_id\x18\x03 \x01(\x0c\x1a\xb3\x01\n\x0f\x45xistingLicense\x12;\n\nlicense_id\x18\x01 \x01(\x0b\x32\'.license_protocol.LicenseIdentification\x12\x1d\n\x15seconds_since_started\x18\x02 \x01(\x03\x12!\n\x19seconds_since_last_played\x18\x03 \x01(\x03\x12!\n\x19session_usage_table_entry\x18\x04 \x01(\x0c\x1a\xf6\x01\n\x08InitData\x12j\n\x0einit_data_type\x18\x01 \x01(\x0e\x32L.license_protocol.LicenseRequest.ContentIdentification.InitData.InitDataType:\x04\x43\x45NC\x12\x11\n\tinit_data\x18\x02 \x01(\x0c\x12\x33\n\x0clicense_type\x18\x03 \x01(\x0e\x32\x1d.license_protocol.LicenseType\x12\x12\n\nrequest_id\x18\x04 \x01(\x0c\"\"\n\x0cInitDataType\x12\x08\n\x04\x43\x45NC\x10\x01\x12\x08\n\x04WEBM\x10\x02\x42\x14\n\x12\x63ontent_id_variant\"0\n\x0bRequestType\x12\x07\n\x03NEW\x10\x01\x12\x0b\n\x07RENEWAL\x10\x02\x12\x0b\n\x07RELEASE\x10\x03\"\xdd\x01\n\nMetricData\x12\x12\n\nstage_name\x18\x01 \x01(\t\x12;\n\x0bmetric_data\x18\x02 \x03(\x0b\x32&.license_protocol.MetricData.TypeValue\x1aT\n\tTypeValue\x12\x35\n\x04type\x18\x01 \x01(\x0e\x32\'.license_protocol.MetricData.MetricType\x12\x10\n\x05value\x18\x02 \x01(\x03:\x01\x30\"(\n\nMetricType\x12\x0b\n\x07LATENCY\x10\x01\x12\r\n\tTIMESTAMP\x10\x02\"K\n\x0bVersionInfo\x12\x1b\n\x13license_sdk_version\x18\x01 \x01(\t\x12\x1f\n\x17license_service_version\x18\x02 \x01(\t\"\xca\x05\n\rSignedMessage\x12\x39\n\x04type\x18\x01 \x01(\x0e\x32+.license_protocol.SignedMessage.MessageType\x12\x0b\n\x03msg\x18\x02 \x01(\x0c\x12\x11\n\tsignature\x18\x03 \x01(\x0c\x12\x13\n\x0bsession_key\x18\x04 \x01(\x0c\x12\x1a\n\x12remote_attestation\x18\x05 \x01(\x0c\x12\x31\n\x0bmetric_data\x18\x06 \x03(\x0b\x32\x1c.license_protocol.MetricData\x12;\n\x14service_version_info\x18\x07 \x01(\x0b\x32\x1d.license_protocol.VersionInfo\x12Y\n\x10session_key_type\x18\x08 \x01(\x0e\x32..license_protocol.SignedMessage.SessionKeyType:\x0fWRAPPED_AES_KEY\x12\x1e\n\x16oemcrypto_core_message\x18\t \x01(\x0c\"\xec\x01\n\x0bMessageType\x12\x13\n\x0fLICENSE_REQUEST\x10\x01\x12\x0b\n\x07LICENSE\x10\x02\x12\x12\n\x0e\x45RROR_RESPONSE\x10\x03\x12\x1f\n\x1bSERVICE_CERTIFICATE_REQUEST\x10\x04\x12\x17\n\x13SERVICE_CERTIFICATE\x10\x05\x12\x0f\n\x0bSUB_LICENSE\x10\x06\x12\x17\n\x13\x43\x41S_LICENSE_REQUEST\x10\x07\x12\x0f\n\x0b\x43\x41S_LICENSE\x10\x08\x12\x1c\n\x18\x45XTERNAL_LICENSE_REQUEST\x10\t\x12\x14\n\x10\x45XTERNAL_LICENSE\x10\n\"S\n\x0eSessionKeyType\x12\r\n\tUNDEFINED\x10\x00\x12\x13\n\x0fWRAPPED_AES_KEY\x10\x01\x12\x1d\n\x19\x45PHERMERAL_ECC_PUBLIC_KEY\x10\x02\"\xef\r\n\x14\x43lientIdentification\x12\x46\n\x04type\x18\x01 \x01(\x0e\x32\x30.license_protocol.ClientIdentification.TokenType:\x06KEYBOX\x12\r\n\x05token\x18\x02 \x01(\x0c\x12\x45\n\x0b\x63lient_info\x18\x03 \x03(\x0b\x32\x30.license_protocol.ClientIdentification.NameValue\x12\x1d\n\x15provider_client_token\x18\x04 \x01(\x0c\x12\x17\n\x0flicense_counter\x18\x05 \x01(\r\x12V\n\x13\x63lient_capabilities\x18\x06 \x01(\x0b\x32\x39.license_protocol.ClientIdentification.ClientCapabilities\x12\x10\n\x08vmp_data\x18\x07 \x01(\x0c\x12T\n\x12\x64\x65vice_credentials\x18\x08 \x03(\x0b\x32\x38.license_protocol.ClientIdentification.ClientCredentials\x1a(\n\tNameValue\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t\x1a\xb5\x08\n\x12\x43lientCapabilities\x12\x1b\n\x0c\x63lient_token\x18\x01 \x01(\x08:\x05\x66\x61lse\x12\x1c\n\rsession_token\x18\x02 \x01(\x08:\x05\x66\x61lse\x12+\n\x1cvideo_resolution_constraints\x18\x03 \x01(\x08:\x05\x66\x61lse\x12j\n\x10max_hdcp_version\x18\x04 \x01(\x0e\x32\x45.license_protocol.ClientIdentification.ClientCapabilities.HdcpVersion:\tHDCP_NONE\x12\x1e\n\x16oem_crypto_api_version\x18\x05 \x01(\r\x12(\n\x19\x61nti_rollback_usage_table\x18\x06 \x01(\x08:\x05\x66\x61lse\x12\x13\n\x0bsrm_version\x18\x07 \x01(\r\x12\x1d\n\x0e\x63\x61n_update_srm\x18\x08 \x01(\x08:\x05\x66\x61lse\x12t\n\x1esupported_certificate_key_type\x18\t \x03(\x0e\x32L.license_protocol.ClientIdentification.ClientCapabilities.CertificateKeyType\x12\x8d\x01\n\x1a\x61nalog_output_capabilities\x18\n \x01(\x0e\x32R.license_protocol.ClientIdentification.ClientCapabilities.AnalogOutputCapabilities:\x15\x41NALOG_OUTPUT_UNKNOWN\x12(\n\x19\x63\x61n_disable_analog_output\x18\x0b \x01(\x08:\x05\x66\x61lse\x12\x1f\n\x14resource_rating_tier\x18\x0c \x01(\r:\x01\x30\"\x80\x01\n\x0bHdcpVersion\x12\r\n\tHDCP_NONE\x10\x00\x12\x0b\n\x07HDCP_V1\x10\x01\x12\x0b\n\x07HDCP_V2\x10\x02\x12\r\n\tHDCP_V2_1\x10\x03\x12\r\n\tHDCP_V2_2\x10\x04\x12\r\n\tHDCP_V2_3\x10\x05\x12\x1b\n\x16HDCP_NO_DIGITAL_OUTPUT\x10\xff\x01\"i\n\x12\x43\x65rtificateKeyType\x12\x0c\n\x08RSA_2048\x10\x00\x12\x0c\n\x08RSA_3072\x10\x01\x12\x11\n\rECC_SECP256R1\x10\x02\x12\x11\n\rECC_SECP384R1\x10\x03\x12\x11\n\rECC_SECP521R1\x10\x04\"\x8d\x01\n\x18\x41nalogOutputCapabilities\x12\x19\n\x15\x41NALOG_OUTPUT_UNKNOWN\x10\x00\x12\x16\n\x12\x41NALOG_OUTPUT_NONE\x10\x01\x12\x1b\n\x17\x41NALOG_OUTPUT_SUPPORTED\x10\x02\x12!\n\x1d\x41NALOG_OUTPUT_SUPPORTS_CGMS_A\x10\x03\x1aj\n\x11\x43lientCredentials\x12\x46\n\x04type\x18\x01 \x01(\x0e\x32\x30.license_protocol.ClientIdentification.TokenType:\x06KEYBOX\x12\r\n\x05token\x18\x02 \x01(\x0c\"s\n\tTokenType\x12\n\n\x06KEYBOX\x10\x00\x12\x1a\n\x16\x44RM_DEVICE_CERTIFICATE\x10\x01\x12\"\n\x1eREMOTE_ATTESTATION_CERTIFICATE\x10\x02\x12\x1a\n\x16OEM_DEVICE_CERTIFICATE\x10\x03\"\xbb\x01\n\x1d\x45ncryptedClientIdentification\x12\x13\n\x0bprovider_id\x18\x01 \x01(\t\x12)\n!service_certificate_serial_number\x18\x02 \x01(\x0c\x12\x1b\n\x13\x65ncrypted_client_id\x18\x03 \x01(\x0c\x12\x1e\n\x16\x65ncrypted_client_id_iv\x18\x04 \x01(\x0c\x12\x1d\n\x15\x65ncrypted_privacy_key\x18\x05 \x01(\x0c\"\x83\x07\n\x0e\x44rmCertificate\x12\x33\n\x04type\x18\x01 \x01(\x0e\x32%.license_protocol.DrmCertificate.Type\x12\x15\n\rserial_number\x18\x02 \x01(\x0c\x12\x1d\n\x15\x63reation_time_seconds\x18\x03 \x01(\r\x12\x1f\n\x17\x65xpiration_time_seconds\x18\x0c \x01(\r\x12\x12\n\npublic_key\x18\x04 \x01(\x0c\x12\x11\n\tsystem_id\x18\x05 \x01(\r\x12\"\n\x16test_device_deprecated\x18\x06 \x01(\x08\x42\x02\x18\x01\x12\x13\n\x0bprovider_id\x18\x07 \x01(\t\x12\x43\n\rservice_types\x18\x08 \x03(\x0e\x32,.license_protocol.DrmCertificate.ServiceType\x12\x42\n\talgorithm\x18\t \x01(\x0e\x32*.license_protocol.DrmCertificate.Algorithm:\x03RSA\x12\x0e\n\x06rot_id\x18\n \x01(\x0c\x12\x46\n\x0e\x65ncryption_key\x18\x0b \x01(\x0b\x32..license_protocol.DrmCertificate.EncryptionKey\x1ag\n\rEncryptionKey\x12\x12\n\npublic_key\x18\x01 \x01(\x0c\x12\x42\n\talgorithm\x18\x02 \x01(\x0e\x32*.license_protocol.DrmCertificate.Algorithm:\x03RSA\"L\n\x04Type\x12\x08\n\x04ROOT\x10\x00\x12\x10\n\x0c\x44\x45VICE_MODEL\x10\x01\x12\n\n\x06\x44\x45VICE\x10\x02\x12\x0b\n\x07SERVICE\x10\x03\x12\x0f\n\x0bPROVISIONER\x10\x04\"\x86\x01\n\x0bServiceType\x12\x18\n\x14UNKNOWN_SERVICE_TYPE\x10\x00\x12\x16\n\x12LICENSE_SERVER_SDK\x10\x01\x12\x1c\n\x18LICENSE_SERVER_PROXY_SDK\x10\x02\x12\x14\n\x10PROVISIONING_SDK\x10\x03\x12\x11\n\rCAS_PROXY_SDK\x10\x04\"d\n\tAlgorithm\x12\x15\n\x11UNKNOWN_ALGORITHM\x10\x00\x12\x07\n\x03RSA\x10\x01\x12\x11\n\rECC_SECP256R1\x10\x02\x12\x11\n\rECC_SECP384R1\x10\x03\x12\x11\n\rECC_SECP521R1\x10\x04\"\xb8\x01\n\x14SignedDrmCertificate\x12\x17\n\x0f\x64rm_certificate\x18\x01 \x01(\x0c\x12\x11\n\tsignature\x18\x02 \x01(\x0c\x12\x36\n\x06signer\x18\x03 \x01(\x0b\x32&.license_protocol.SignedDrmCertificate\x12<\n\x0ehash_algorithm\x18\x04 \x01(\x0e\x32$.license_protocol.HashAlgorithmProto\"\xd5\x05\n\x10WidevinePsshData\x12\x0f\n\x07key_ids\x18\x02 \x03(\x0c\x12\x12\n\ncontent_id\x18\x04 \x01(\x0c\x12\x1b\n\x13\x63rypto_period_index\x18\x07 \x01(\r\x12\x19\n\x11protection_scheme\x18\t \x01(\r\x12\x1d\n\x15\x63rypto_period_seconds\x18\n \x01(\r\x12=\n\x04type\x18\x0b \x01(\x0e\x32\'.license_protocol.WidevinePsshData.Type:\x06SINGLE\x12\x14\n\x0ckey_sequence\x18\x0c \x01(\r\x12\x11\n\tgroup_ids\x18\r \x03(\x0c\x12\x45\n\rentitled_keys\x18\x0e \x03(\x0b\x32..license_protocol.WidevinePsshData.EntitledKey\x12\x15\n\rvideo_feature\x18\x0f \x01(\t\x12\x43\n\talgorithm\x18\x01 \x01(\x0e\x32,.license_protocol.WidevinePsshData.AlgorithmB\x02\x18\x01\x12\x14\n\x08provider\x18\x03 \x01(\tB\x02\x18\x01\x12\x16\n\ntrack_type\x18\x05 \x01(\tB\x02\x18\x01\x12\x12\n\x06policy\x18\x06 \x01(\tB\x02\x18\x01\x12\x1b\n\x0fgrouped_license\x18\x08 \x01(\x0c\x42\x02\x18\x01\x1az\n\x0b\x45ntitledKey\x12\x1a\n\x12\x65ntitlement_key_id\x18\x01 \x01(\x0c\x12\x0e\n\x06key_id\x18\x02 \x01(\x0c\x12\x0b\n\x03key\x18\x03 \x01(\x0c\x12\n\n\x02iv\x18\x04 \x01(\x0c\x12&\n\x1a\x65ntitlement_key_size_bytes\x18\x05 \x01(\r:\x02\x33\x32\"5\n\x04Type\x12\n\n\x06SINGLE\x10\x00\x12\x0f\n\x0b\x45NTITLEMENT\x10\x01\x12\x10\n\x0c\x45NTITLED_KEY\x10\x02\"(\n\tAlgorithm\x12\x0f\n\x0bUNENCRYPTED\x10\x00\x12\n\n\x06\x41\x45SCTR\x10\x01\"\xc6\x01\n\nFileHashes\x12\x0e\n\x06signer\x18\x01 \x01(\x0c\x12:\n\nsignatures\x18\x02 \x03(\x0b\x32&.license_protocol.FileHashes.Signature\x1al\n\tSignature\x12\x10\n\x08\x66ilename\x18\x01 \x01(\t\x12\x14\n\x0ctest_signing\x18\x02 \x01(\x08\x12\x12\n\nSHA512Hash\x18\x03 \x01(\x0c\x12\x10\n\x08main_exe\x18\x04 \x01(\x08\x12\x11\n\tsignature\x18\x05 \x01(\x0c*8\n\x0bLicenseType\x12\r\n\tSTREAMING\x10\x01\x12\x0b\n\x07OFFLINE\x10\x02\x12\r\n\tAUTOMATIC\x10\x03*\xd9\x01\n\x1aPlatformVerificationStatus\x12\x17\n\x13PLATFORM_UNVERIFIED\x10\x00\x12\x15\n\x11PLATFORM_TAMPERED\x10\x01\x12\x1e\n\x1aPLATFORM_SOFTWARE_VERIFIED\x10\x02\x12\x1e\n\x1aPLATFORM_HARDWARE_VERIFIED\x10\x03\x12\x1c\n\x18PLATFORM_NO_VERIFICATION\x10\x04\x12-\n)PLATFORM_SECURE_STORAGE_SOFTWARE_VERIFIED\x10\x05*D\n\x0fProtocolVersion\x12\x0f\n\x0bVERSION_2_0\x10\x14\x12\x0f\n\x0bVERSION_2_1\x10\x15\x12\x0f\n\x0bVERSION_2_2\x10\x16*\x86\x01\n\x12HashAlgorithmProto\x12\x1e\n\x1aHASH_ALGORITHM_UNSPECIFIED\x10\x00\x12\x18\n\x14HASH_ALGORITHM_SHA_1\x10\x01\x12\x1a\n\x16HASH_ALGORITHM_SHA_256\x10\x02\x12\x1a\n\x16HASH_ALGORITHM_SHA_384\x10\x03\x42\x02H\x03')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'license_protocol_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'H\003'
  _globals['_DRMCERTIFICATE'].fields_by_name['test_device_deprecated']._loaded_options = None
  _globals['_DRMCERTIFICATE'].fields_by_name['test_device_deprecated']._serialized_options = b'\030\001'
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['algorithm']._loaded_options = None
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['algorithm']._serialized_options = b'\030\001'
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['provider']._loaded_options = None
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['provider']._serialized_options = b'\030\001'
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['track_type']._loaded_options = None
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['track_type']._serialized_options = b'\030\001'
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['policy']._loaded_options = None
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['policy']._serialized_options = b'\030\001'
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['grouped_license']._loaded_options = None
  _globals['_WIDEVINEPSSHDATA'].fields_by_name['grouped_license']._serialized_options = b'\030\001'
  _globals['_LICENSETYPE']._serialized_start=9826
  _globals['_LICENSETYPE']._serialized_end=9882
  _globals['_PLATFORMVERIFICATIONSTATUS']._serialized_start=9885
  _globals['_PLATFORMVERIFICATIONSTATUS']._serialized_end=10102
  _globals['_PROTOCOLVERSION']._serialized_start=10104
  _globals['_PROTOCOLVERSION']._serialized_end=10172
  _globals['_HASHALGORITHMPROTO']._serialized_start=10175
  _globals['_HASHALGORITHMPROTO']._serialized_end=10309
  _globals['_LICENSEIDENTIFICATION']._serialized_start=45
  _globals['_LICENSEIDENTIFICATION']._serialized_end=223
  _globals['_LICENSE']._serialized_start=226
  _globals['_LICENSE']._serialized_end=3246
  _globals['_LICENSE_POLICY']._serialized_start=698
  _globals['_LICENSE_POLICY']._serialized_end=1256
  _globals['_LICENSE_KEYCONTAINER']._serialized_start=1259
  _globals['_LICENSE_KEYCONTAINER']._serialized_end=3246
  _globals['_LICENSE_KEYCONTAINER_KEYCONTROL']._serialized_start=1985
  _globals['_LICENSE_KEYCONTAINER_KEYCONTROL']._serialized_end=2036
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION']._serialized_start=2039
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION']._serialized_end=2674
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION_HDCP']._serialized_start=2428
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION_HDCP']._serialized_end=2549
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION_CGMS']._serialized_start=2551
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION_CGMS']._serialized_end=2618
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION_HDCPSRMRULE']._serialized_start=2620
  _globals['_LICENSE_KEYCONTAINER_OUTPUTPROTECTION_HDCPSRMRULE']._serialized_end=2674
  _globals['_LICENSE_KEYCONTAINER_VIDEORESOLUTIONCONSTRAINT']._serialized_start=2677
  _globals['_LICENSE_KEYCONTAINER_VIDEORESOLUTIONCONSTRAINT']._serialized_end=2852
  _globals['_LICENSE_KEYCONTAINER_OPERATORSESSIONKEYPERMISSIONS']._serialized_start=2855
  _globals['_LICENSE_KEYCONTAINER_OPERATORSESSIONKEYPERMISSIONS']._serialized_end=3012
  _globals['_LICENSE_KEYCONTAINER_KEYTYPE']._serialized_start=3014
  _globals['_LICENSE_KEYCONTAINER_KEYTYPE']._serialized_end=3122
  _globals['_LICENSE_KEYCONTAINER_SECURITYLEVEL']._serialized_start=3124
  _globals['_LICENSE_KEYCONTAINER_SECURITYLEVEL']._serialized_end=3246
  _globals['_LICENSEREQUEST']._serialized_start=3249
  _globals['_LICENSEREQUEST']._serialized_end=4820
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION']._serialized_start=3702
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION']._serialized_end=4770
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_WIDEVINEPSSHDATA']._serialized_start=4105
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_WIDEVINEPSSHDATA']._serialized_end=4215
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_WEBMKEYID']._serialized_start=4217
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_WEBMKEYID']._serialized_end=4317
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_EXISTINGLICENSE']._serialized_start=4320
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_EXISTINGLICENSE']._serialized_end=4499
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_INITDATA']._serialized_start=4502
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_INITDATA']._serialized_end=4748
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_INITDATA_INITDATATYPE']._serialized_start=4714
  _globals['_LICENSEREQUEST_CONTENTIDENTIFICATION_INITDATA_INITDATATYPE']._serialized_end=4748
  _globals['_LICENSEREQUEST_REQUESTTYPE']._serialized_start=4772
  _globals['_LICENSEREQUEST_REQUESTTYPE']._serialized_end=4820
  _globals['_METRICDATA']._serialized_start=4823
  _globals['_METRICDATA']._serialized_end=5044
  _globals['_METRICDATA_TYPEVALUE']._serialized_start=4918
  _globals['_METRICDATA_TYPEVALUE']._serialized_end=5002
  _globals['_METRICDATA_METRICTYPE']._serialized_start=5004
  _globals['_METRICDATA_METRICTYPE']._serialized_end=5044
  _globals['_VERSIONINFO']._serialized_start=5046
  _globals['_VERSIONINFO']._serialized_end=5121
  _globals['_SIGNEDMESSAGE']._serialized_start=5124
  _globals['_SIGNEDMESSAGE']._serialized_end=5838
  _globals['_SIGNEDMESSAGE_MESSAGETYPE']._serialized_start=5517
  _globals['_SIGNEDMESSAGE_MESSAGETYPE']._serialized_end=5753
  _globals['_SIGNEDMESSAGE_SESSIONKEYTYPE']._serialized_start=5755
  _globals['_SIGNEDMESSAGE_SESSIONKEYTYPE']._serialized_end=5838
  _globals['_CLIENTIDENTIFICATION']._serialized_start=5841
  _globals['_CLIENTIDENTIFICATION']._serialized_end=7616
  _globals['_CLIENTIDENTIFICATION_NAMEVALUE']._serialized_start=6271
  _globals['_CLIENTIDENTIFICATION_NAMEVALUE']._serialized_end=6311
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES']._serialized_start=6314
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES']._serialized_end=7391
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES_HDCPVERSION']._serialized_start=7012
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES_HDCPVERSION']._serialized_end=7140
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES_CERTIFICATEKEYTYPE']._serialized_start=7142
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES_CERTIFICATEKEYTYPE']._serialized_end=7247
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES_ANALOGOUTPUTCAPABILITIES']._serialized_start=7250
  _globals['_CLIENTIDENTIFICATION_CLIENTCAPABILITIES_ANALOGOUTPUTCAPABILITIES']._serialized_end=7391
  _globals['_CLIENTIDENTIFICATION_CLIENTCREDENTIALS']._serialized_start=7393
  _globals['_CLIENTIDENTIFICATION_CLIENTCREDENTIALS']._serialized_end=7499
  _globals['_CLIENTIDENTIFICATION_TOKENTYPE']._serialized_start=7501
  _globals['_CLIENTIDENTIFICATION_TOKENTYPE']._serialized_end=7616
  _globals['_ENCRYPTEDCLIENTIDENTIFICATION']._serialized_start=7619
  _globals['_ENCRYPTEDCLIENTIDENTIFICATION']._serialized_end=7806
  _globals['_DRMCERTIFICATE']._serialized_start=7809
  _globals['_DRMCERTIFICATE']._serialized_end=8708
  _globals['_DRMCERTIFICATE_ENCRYPTIONKEY']._serialized_start=8288
  _globals['_DRMCERTIFICATE_ENCRYPTIONKEY']._serialized_end=8391
  _globals['_DRMCERTIFICATE_TYPE']._serialized_start=8393
  _globals['_DRMCERTIFICATE_TYPE']._serialized_end=8469
  _globals['_DRMCERTIFICATE_SERVICETYPE']._serialized_start=8472
  _globals['_DRMCERTIFICATE_SERVICETYPE']._serialized_end=8606
  _globals['_DRMCERTIFICATE_ALGORITHM']._serialized_start=8608
  _globals['_DRMCERTIFICATE_ALGORITHM']._serialized_end=8708
  _globals['_SIGNEDDRMCERTIFICATE']._serialized_start=8711
  _globals['_SIGNEDDRMCERTIFICATE']._serialized_end=8895
  _globals['_WIDEVINEPSSHDATA']._serialized_start=8898
  _globals['_WIDEVINEPSSHDATA']._serialized_end=9623
  _globals['_WIDEVINEPSSHDATA_ENTITLEDKEY']._serialized_start=9404
  _globals['_WIDEVINEPSSHDATA_ENTITLEDKEY']._serialized_end=9526
  _globals['_WIDEVINEPSSHDATA_TYPE']._serialized_start=9528
  _globals['_WIDEVINEPSSHDATA_TYPE']._serialized_end=9581
  _globals['_WIDEVINEPSSHDATA_ALGORITHM']._serialized_start=9583
  _globals['_WIDEVINEPSSHDATA_ALGORITHM']._serialized_end=9623
  _globals['_FILEHASHES']._serialized_start=9626
  _globals['_FILEHASHES']._serialized_end=9824
  _globals['_FILEHASHES_SIGNATURE']._serialized_start=9716
  _globals['_FILEHASHES_SIGNATURE']._serialized_end=9824

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

class _Structures:
    magic = Const(b"WVD")

    header = Struct(
        "signature" / magic,
        "version" / Int8ub
    )

                                                                            
    v2 = Struct(
        "signature" / magic,
        "version" / Const(Int8ub, 2),
        "type_" / CEnum(
            Int8ub,
            **{t.name: t.value for t in DeviceTypes}
        ),
        "security_level" / Int8ub,
        "flags" / Padded(1, COptional(BitStruct(
                                     
            Padding(8)
        ))),
        "private_key_len" / Int16ub,
        "private_key" / Bytes(this.private_key_len),
        "client_id_len" / Int16ub,
        "client_id" / Bytes(this.client_id_len)
    )

                                                                                     
    v1 = Struct(
        "signature" / magic,
        "version" / Const(Int8ub, 1),
        "type_" / CEnum(
            Int8ub,
            **{t.name: t.value for t in DeviceTypes}
        ),
        "security_level" / Int8ub,
        "flags" / Padded(1, COptional(BitStruct(
                                     
            Padding(8)
        ))),
        "private_key_len" / Int16ub,
        "private_key" / Bytes(this.private_key_len),
        "client_id_len" / Int16ub,
        "client_id" / Bytes(this.client_id_len),
        "vmp_len" / Int16ub,
        "vmp" / Bytes(this.vmp_len)
    )

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

    @classmethod
    def from_files(
        cls,
        private_key: Union[Path, str, bytes],
        client_id: Union[Path, str, bytes],
        vmp: Optional[Union[Path, str, bytes]] = None,
        type_: Union[DeviceTypes, str] = DeviceTypes.ANDROID,
        security_level: int = 3,
        flags: Optional[dict] = None
    ) -> Device:
        private_key_bytes = private_key if isinstance(private_key, bytes) else Path(private_key).read_bytes()
        client_id_bytes = client_id if isinstance(client_id, bytes) else Path(client_id).read_bytes()
        device = cls(
            type_=type_,
            security_level=security_level,
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
    def load_from_files(cls, private_key: Union[Path, str, bytes], client_id: Union[Path, str, bytes], vmp: Optional[Union[Path, str, bytes]] = None, type: Union[DeviceTypes, str] = DeviceTypes.ANDROID, type_: Optional[Union[DeviceTypes, str]] = None, security_level: int = 3, flags: Optional[dict] = None) -> Device:
        selected_type = type_ if type_ is not None else type
        selected_vmp = None
        if vmp is not None:
            if isinstance(vmp, bytes):
                selected_vmp = vmp
            else:
                vmp_path = Path(vmp)
                if vmp_path.exists() and vmp_path.is_file():
                    selected_vmp = vmp_path
        return cls.from_files(private_key=private_key,
                              client_id=client_id,
                              vmp=selected_vmp,
                              type_=selected_type,
                              security_level=security_level,
                              flags=flags)

    @classmethod
    def from_directory(cls, path: Union[Path, str], type_: Union[DeviceTypes, str] = DeviceTypes.ANDROID, security_level: int = 3, flags: Optional[dict] = None) -> Device:
        directory = Path(path)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Device directory does not exist: {directory}")
        private_key_path = directory / "device_private_key"
        client_id_path = directory / "device_client_id_blob"
        vmp_path = directory / "device_vmp_blob"
        if not private_key_path.exists():
            raise FileNotFoundError(f"Missing device private key file: {private_key_path}")
        if not client_id_path.exists():
            raise FileNotFoundError(f"Missing device client ID blob file: {client_id_path}")
        return cls.from_files(private_key=private_key_path, client_id=client_id_path, vmp=vmp_path if vmp_path.exists() else None,
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
            v1_struct.flags = Container()                                             

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
            except ConstructError as e:
                raise ValueError(f"Migration failed, {e}")

        try:
            return cls.loads(data)
        except ConstructError as e:
            raise ValueError(f"Device Data seems to be corrupt or invalid, or migration failed, {e}")


__all__ = ("Device", "DeviceTypes")


class PSSH:
    class SystemId:
        Widevine = UUID(hex="edef8ba979d64acea3c827dcd51d21ed")
        PlayReady = UUID(hex="9a04f07998404286ab92e65be0885f95")

    def __init__(self, data: Union[Container, str, bytes], strict: bool = False):
        if not data:
            raise ValueError("Data must not be empty.")

        if isinstance(data, Container):
            box = data
        else:
            if isinstance(data, str):
                try:
                    data = base64.b64decode(data)
                except (binascii.Error, binascii.Incomplete) as e:
                    raise binascii.Error(f"Could not decode data as Base64, {e}")

            if not isinstance(data, bytes):
                raise TypeError(f"Expected data to be a {Container}, bytes, or base64, not {data!r}")

            try:
                box = Box.parse(data)
            except (IOError, construct.ConstructError):             
                try:
                    widevine_pssh_data = WidevinePsshData()
                    widevine_pssh_data.ParseFromString(data)
                    data_serialized = widevine_pssh_data.SerializeToString()
                    if data_serialized != data:                                   
                        raise DecodeError()
                    box = Box.parse(Box.build(dict(
                        type=b"pssh",
                        version=0,
                        flags=0,
                        system_ID=PSSH.SystemId.Widevine,
                        init_data=data_serialized
                    )))
                except DecodeError:                              
                    if "</WRMHEADER>".encode("utf-16-le") in data:
                                                                                                        
                        box = Box.parse(Box.build(dict(
                            type=b"pssh",
                            version=0,
                            flags=0,
                            system_ID=PSSH.SystemId.PlayReady,
                            init_data=data
                        )))
                    elif strict:
                        raise DecodeError(f"Could not parse data as a {Container} nor a {WidevinePsshData}.")
                    else:                                               
                        box = Box.parse(Box.build(dict(type=b"pssh",
                                                       version=0,
                                                       flags=0,
                                                       system_ID=PSSH.SystemId.Widevine,
                                                       init_data=data)))
        self.version = box.version
        self.flags = box.flags
        self.system_id = box.system_ID
        self.__key_ids = box.key_IDs
        self.init_data = box.init_data

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
        """Craft a new version 0 or 1 PSSH Box."""
        if not system_id:
            raise ValueError("A System ID must be specified.")
        if not isinstance(system_id, UUID):
            raise TypeError(f"Expected system_id to be a UUID, not {system_id!r}")

        if key_ids is not None and not isinstance(key_ids, list):
            raise TypeError(f"Expected key_ids to be a list not {key_ids!r}")

        if init_data is not None and not isinstance(init_data, (WidevinePsshData, str, bytes)):
            raise TypeError(f"Expected init_data to be a {WidevinePsshData}, base64, or bytes, not {init_data!r}")

        if not isinstance(version, int):
            raise TypeError(f"Expected version to be an int not {version!r}")
        if version not in (0, 1):
            raise ValueError(f"Invalid version, must be either 0 or 1, not {version}.")

        if not isinstance(flags, int):
            raise TypeError(f"Expected flags to be an int not {flags!r}")
        if flags < 0:
            raise ValueError("Invalid flags, cannot be less than 0.")

        if version == 0 and key_ids is not None and init_data is not None:
                                                                                                            
            raise ValueError("Version 0 PSSH boxes must use only init_data, not init_data and key_ids.")
        elif version == 1:
                                                                                                       
                                                                             
            if init_data is None and key_ids is None:
                raise ValueError("Version 1 PSSH boxes must use either init_data or key_ids but neither were provided")

        if init_data is not None:
            if isinstance(init_data, WidevinePsshData):
                init_data = init_data.SerializeToString()
            elif isinstance(init_data, str):
                if all(c in string.hexdigits for c in init_data):
                    init_data = bytes.fromhex(init_data)
                else:
                    init_data = base64.b64decode(init_data)
            elif not isinstance(init_data, bytes):
                raise TypeError(
                    f"Expecting init_data to be {WidevinePsshData}, hex, base64, or bytes, not {init_data!r}"
                )

        pssh = cls(Box.parse(Box.build(dict(type=b"pssh",
                                            version=version,
                                            flags=flags,
                                            system_ID=system_id,
                                            init_data=[init_data, b""][init_data is None]))))

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
                (
                    UUID(bytes=key_id) if len(key_id) == 16 else          
                    UUID(hex=key_id.decode()) if len(key_id) == 32 else                 
                    UUID(int=int.from_bytes(key_id, "big"))                      
                )
                for key_id in cenc_header.key_ids
            ]

        if self.system_id == PSSH.SystemId.PlayReady:
                                                           
                                                                                                       
            pro_data = BytesIO(self.init_data)
            pro_length = int.from_bytes(pro_data.read(4), "little")
            if pro_length != len(self.init_data):
                raise ValueError("The PlayReadyObject seems to be corrupt (too big or small, or missing data).")
            pro_record_count = int.from_bytes(pro_data.read(2), "little")

            for _ in range(pro_record_count):
                prr_type = int.from_bytes(pro_data.read(2), "little")
                prr_length = int.from_bytes(pro_data.read(2), "little")
                prr_value = pro_data.read(prr_length)
                if prr_type != 0x01:                                           
                    continue

                wrm_ns = {"wrm": "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader"}
                prr_header = XML(prr_value.decode("utf-16-le"))
                prr_header_version = prr_header.get("version")
                if prr_header_version == "4.0.0.0":
                    key_ids = [
                        x.text
                        for x in prr_header.findall("./wrm:DATA/wrm:KID", wrm_ns)
                        if x.text
                    ]
                elif prr_header_version == "4.1.0.0":
                    key_ids = [
                        x.attrib["VALUE"]
                        for x in prr_header.findall("./wrm:DATA/wrm:PROTECTINFO/wrm:KID", wrm_ns)
                    ]
                elif prr_header_version in ("4.2.0.0", "4.3.0.0"):                      
                    key_ids = [
                        x.attrib["VALUE"]
                        for x in prr_header.findall("./wrm:DATA/wrm:PROTECTINFO/wrm:KIDS/wrm:KID", wrm_ns)
                    ]
                else:
                    raise ValueError(f"Unsupported PlayReadyHeader version {prr_header_version}")

                return [
                    UUID(bytes=base64.b64decode(key_id))
                    for key_id in key_ids
                ]

            raise ValueError("Unsupported PlayReadyObject, no PlayReadyHeader within the object.")

        raise ValueError(f"This PSSH is not supported by key_ids() property, {self.dumps()}")

    def dump(self) -> bytes:
        return Box.build(dict(
            type=b"pssh",
            version=self.version,
            flags=self.flags,
            system_ID=self.system_id,
            key_IDs=self.key_ids if self.version == 1 and self.key_ids else None,
            init_data=self.init_data
        ))

    def dumps(self) -> str:
        """Export the PSSH object as a full PSSH box in base64 form."""
        return base64.b64encode(self.dump()).decode()

    def to_widevine(self) -> None:
        """
        Convert PlayReady PSSH data to Widevine PSSH data.

        There's only a limited amount of information within a PlayReady PSSH header that
        can be used in a Widevine PSSH Header. The converted data may or may not result
        in an accepted PSSH. It depends on what the License Server is expecting.
        """
        if self.system_id == PSSH.SystemId.Widevine:
            raise ValueError("This is already a Widevine PSSH")

        widevine_pssh_data = WidevinePsshData(
            key_ids=[x.bytes for x in self.key_ids],
            algorithm="AESCTR"
        )

        if self.version == 1:                                                       
            self.__key_ids = self.key_ids

        self.init_data = widevine_pssh_data.SerializeToString()
        self.system_id = PSSH.SystemId.Widevine

    def to_playready(self, la_url: Optional[str] = None, lui_url: Optional[str] = None, ds_id: Optional[bytes] = None, decryptor_setup: Optional[str] = None, custom_data: Optional[str] = None) -> None:
        
        if self.system_id == PSSH.SystemId.PlayReady:
            raise ValueError("This is already a PlayReady PSSH")

        key_ids_xml = ""
        for key_id in self.key_ids:
                                                                                                
            key_ids_xml += f"""
            <KID ALGID="AESCTR" VALUE="{base64.b64encode(key_id.bytes).decode()}"></KID>
            """

        prr_value = f"""
        <WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.3.0.0">
            <DATA>
                <PROTECTINFO>
                    <KIDS>{key_ids_xml}</KIDS>
                </PROTECTINFO>
                {'<LA_URL>%s</LA_URL>' % la_url if la_url else ''}
                {'<LUI_URL>%s</LUI_URL>' % lui_url if lui_url else ''}
                {'<DS_ID>%s</DS_ID>' % base64.b64encode(ds_id).decode() if ds_id else ''}
                {'<DECRYPTORSETUP>%s</DECRYPTORSETUP>' % decryptor_setup if decryptor_setup else ''}
                {'<CUSTOMATTRIBUTES xmlns="">%s</CUSTOMATTRIBUTES>' % custom_data if custom_data else ''}
            </DATA>
        </WRMHEADER>
        """.encode("utf-16-le")

        prr_length = len(prr_value).to_bytes(2, "little")
        prr_type = (1).to_bytes(2, "little")                       
        pro_record_count = (1).to_bytes(2, "little")
        pro = pro_record_count + prr_type + prr_length + prr_value
        pro = (len(pro) + 4).to_bytes(4, "little") + pro

        self.init_data = pro
        self.system_id = PSSH.SystemId.PlayReady

    def set_key_ids(self, key_ids: list[Union[UUID, str, bytes]]) -> None:
        if self.system_id != PSSH.SystemId.Widevine:
                                                                             
            raise ValueError(f"Only Widevine PSSH Boxes are supported, not {self.system_id}.")

        key_id_uuids = self.parse_key_ids(key_ids)

        if self.version == 1 or self.__key_ids:                                                        
            self.__key_ids = key_id_uuids
        cenc_header = WidevinePsshData()
        cenc_header.ParseFromString(self.init_data)

        cenc_header.key_ids[:] = [
            key_id.bytes
            for key_id in key_id_uuids
        ]
        self.init_data = cenc_header.SerializeToString()

    @staticmethod
    def parse_key_ids(key_ids: list[Union[UUID, str, bytes]]) -> list[UUID]:
        if not isinstance(key_ids, list):
            raise TypeError(f"Expected key_ids to be a list, not {key_ids!r}")

        if not all(isinstance(x, (UUID, str, bytes)) for x in key_ids):
            raise TypeError("Some items of key_ids are not a UUID, str, or bytes. Unsure how to continue...")

        uuids = [
            UUID(bytes=key_id_b)
            for key_id in key_ids
            for key_id_b in [
                key_id.bytes if isinstance(key_id, UUID) else
                (
                    bytes.fromhex(key_id) if all(c in string.hexdigits for c in key_id) else
                    base64.b64decode(key_id)
                ) if isinstance(key_id, str) else
                key_id
            ]
        ]
        return uuids

__all__ = ("PSSH",)

def get_binary_path(*names: str) -> Optional[Path]:
    """Get the path of the first found binary name."""
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
        if license_type not in LicenseType.keys():
            raise InvalidLicenseType(
                f"Invalid license_type value of '{license_type}'. "
                f"Available values: {LicenseType.keys()}"
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
            raise FileNotFoundError(f"Input file does not exist, {input_file}")
        if output_file.is_file() and not exists_ok:
            raise FileExistsError(f"Output file already exists, {output_file}")

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


def command_info(args: argparse.Namespace) -> int:
    device = build_device_from_args(args)
    client_info = {entry.name: entry.value for entry in device.client_id.client_info}
    result = {
        "type": device.type.name,
        "system_id": device.system_id,
        "security_level": device.security_level,
        "flags": dict(device.flags),
        "client_info": client_info,
        "has_vmp": bool(device.client_id.vmp_data)
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
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
    company = (
        client_info.get("company_name")
        or client_info.get("manufacturer")
        or client_info.get("vendor")
        or "unknown"
    )
    model = (
        client_info.get("model_name")
        or client_info.get("model")
        or client_info.get("device_name")
        or "device"
    )
    name = f"{company} {model}"
    if client_info.get("widevine_cdm_version"):
        name += f" {client_info['widevine_cdm_version']}"
    name += f" {crc32(data).to_bytes(4, 'big').hex()}"
    try:
        name = unidecode(name.strip().lower().replace(" ", "_"))
    except UnidecodeError as exc:
        raise ValueError(f"Failed to sanitize WVD name, {exc}") from exc
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("._-")
    return f"{name}_{device.system_id}_l{device.security_level}.wvd"


def command_create_wvd(args: argparse.Namespace) -> int:
    device_type = normalize_device_type(args.type)
    if getattr(args, "device_dir", None):
        device = Device.from_directory(
            path=args.device_dir,
            type_=device_type,
            security_level=args.level,
            flags=None
        )
    else:
        if not args.key:
            raise ValueError("A private key file is required when --device-dir is not used.")
        if not args.client_id:
            raise ValueError("A client ID blob file is required when --device-dir is not used.")
        device = Device.from_files(
            private_key=args.key,
            client_id=args.client_id,
            vmp=args.vmp,
            type_=device_type,
            security_level=args.level,
            flags=None
        )
    wvd_data = device.dumps()
    if args.output:
        output = Path(args.output)
        if output.suffix:
            if output.suffix.lower() != ".wvd":
                logging.getLogger("create-wvd").warning(
                    "Saving WVD with extension '%s', but '.wvd' is recommended.",
                    output.suffix
                )
            output_path = output
        else:
            output_path = output / build_wvd_name(device, wvd_data)
    else:
        output_path = Path.cwd() / build_wvd_name(device, wvd_data)
    if output_path.exists() and not args.overwrite:
        raise FileExistsError(f"Output already exists: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(wvd_data)
    print(f"Created Widevine Device file: {output_path}")
    print(f"Type: {device.type.name}")
    print(f"System ID: {device.system_id}")
    print(f"Security Level: {device.security_level}")
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
        capabilities = MessageToDict(
            device.client_id,
            preserving_proto_field_name=True
        ).get("client_capabilities", {})
    except Exception:
        capabilities = {}
    lines = [
        "wvd:",
        f"  device_type: {device.type.name}",
        f"  security_level: {device.security_level}",
        "client_info:",
    ]
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
        raise FileNotFoundError(f"WVD file does not exist: {input_path}")
    device = Device.load(input_path)
    output_root = Path(args.output) if args.output else Path.cwd()
    output = output_root / input_path.stem
    if output.exists():
        if any(output.iterdir()) and not args.overwrite:
            raise FileExistsError(f"Output directory is not empty: {output}")
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
            raise FileExistsError(f"Output already exists: {target}")
    write_metadata_file(metadata_path, device)
    private_key_pem_path.write_text(device.private_key.export_key().decode(), encoding="utf-8")
    private_key_der_path.write_bytes(device.private_key.export_key(format="DER"))
    client_id_path.write_bytes(device.client_id.SerializeToString())
    if device.client_id.vmp_data:
        vmp_path.write_bytes(device.client_id.vmp_data)
    print(f"Exported Widevine Device file: {input_path}")
    print(f"Output directory: {output}")
    print(f"Exported metadata: {metadata_path}")
    print(f"Exported private key PEM: {private_key_pem_path}")
    print(f"Exported private key DER: {private_key_der_path}")
    print(f"Exported client ID: {client_id_path}")
    if device.client_id.vmp_data:
        print(f"Exported VMP: {vmp_path}")
    else:
        print("No VMP data available.")
    return 0


def command_migrate_wvd(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists() and not args.overwrite:
        raise FileExistsError(f"Output already exists: {output}")
    device = Device.migrate(Path(args.input).read_bytes())
    device.dump(output)
    print(f"Migrated WVD file: {output}")
    return 0


def command_license(args: argparse.Namespace) -> int:
    device = build_device_from_args(args)
    pssh = PSSH(args.pssh)
    cdm = Cdm.from_device(device)
    session_id = cdm.open()
    try:
        if args.privacy and args.certificate:
            cdm.set_service_certificate(session_id, read_binary_argument(args.certificate))
        challenge = cdm.get_license_challenge(session_id, pssh, args.license_type, privacy_mode=args.privacy)
        if args.challenge_output:
            Path(args.challenge_output).write_bytes(challenge)
        if not args.server and not args.license_response:
            print(base64.b64encode(challenge).decode())
            return 0
        if args.license_response:
            license_message = read_binary_argument(args.license_response)
        else:
            response = requests.post(args.server, headers=parse_headers(args.header), data=challenge)
            response.raise_for_status()
            license_message = response.content
        cdm.parse_license(session_id, license_message)
        for key in cdm.get_keys(session_id):
            if args.include_non_content or key.type == "CONTENT":
                print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")
    finally:
        cdm.close(session_id)
    return 0


def command_pssh(args: argparse.Namespace) -> int:
    pssh = PSSH(args.input)
    if args.to_widevine:
        pssh.to_widevine()
    if args.set_key_id:
        pssh.set_key_ids([UUID(value) for value in args.set_key_id])
    if args.output == "base64":
        print(pssh.dumps())
    elif args.output == "hex":
        print(pssh.dump().hex())
    elif args.output == "json":
        data = {
            "system_id": str(pssh.system_id),
            "key_ids": [str(key_id) for key_id in pssh.key_ids],
            "init_data": pssh.init_data.hex() if isinstance(pssh.init_data, bytes) else str(pssh.init_data),
            "box": pssh.dump().hex()
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        sys.stdout.buffer.write(pssh.dump())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pywv",
        description="Single-file Widevine utility with integrated proto, WVD, blob, key, local CDM, and PSSH support."
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("-v", "--version", action="store_true", help="Print version information.")
    sub = parser.add_subparsers(dest="cmd", required=False)

    sp = sub.add_parser("info", help="Show information about a WVD file, device directory, or key/blob pair.")
    sp.add_argument("-w", "--wvd")
    sp.add_argument("-D", "--device-dir")
    sp.add_argument("-k", "--key")
    sp.add_argument("-c", "--client-id")
    sp.add_argument("-vmp", "--vmp")
    sp.add_argument("-t", "--type", default="ANDROID", help="Device type: ANDROID/android or CHROME/chrome.")
    sp.add_argument("-l", "--level", type=int, default=3)
    sp.set_defaults(func=command_info)

    sp = sub.add_parser("create-wvd", help="Create a WVD v2 file from a device directory or key/blob files.")
    sp.add_argument("-D", "--device-dir")
    sp.add_argument("-k", "--key")
    sp.add_argument("-c", "--client-id")
    sp.add_argument("-vmp", "--vmp")
    sp.add_argument("-t", "--type", default="ANDROID", help="Device type: ANDROID/android or CHROME/chrome.")
    sp.add_argument("-l", "--level", type=int, default=3)
    sp.add_argument("-o", "--output", default=None)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(func=command_create_wvd)

    sp = sub.add_parser("export-wvd", help="Export a WVD file into key, blob, and optional VMP files.")
    sp.add_argument("input", nargs="?")
    sp.add_argument("-o", "--output", default=None)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(func=command_export_wvd)

    sp = sub.add_parser("migrate-wvd", help="Migrate a WVD v1 file to WVD v2.")
    sp.add_argument("input")
    sp.add_argument("-o", "--output", default=None)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(func=command_migrate_wvd)

    sp = sub.add_parser("license", help="Create a license challenge and optionally parse a license response.")
    sp.add_argument("--pssh", required=True)
    sp.add_argument("--server")
    sp.add_argument("-H", "--header", action="append", default=[])
    sp.add_argument("-w", "--wvd")
    sp.add_argument("-D", "--device-dir")
    sp.add_argument("-k", "--key")
    sp.add_argument("-c", "--client-id")
    sp.add_argument("-vmp", "--vmp")
    sp.add_argument("-t", "--type", default="ANDROID", help="Device type: ANDROID/android or CHROME/chrome.")
    sp.add_argument("-l", "--level", type=int, default=3)
    sp.add_argument("--certificate")
    sp.add_argument("--privacy", action="store_true")
    sp.add_argument("--license-type", default="STREAMING", choices=LicenseType.keys())
    sp.add_argument("--challenge-output")
    sp.add_argument("--license-response")
    sp.add_argument("--include-non-content", action="store_true")
    sp.set_defaults(func=command_license)

    sp = sub.add_parser("pssh", help="Inspect or rewrite PSSH data.")
    sp.add_argument("input")
    sp.add_argument("-o", "--output", default="base64", choices=["base64", "hex", "json", "raw"])
    sp.add_argument("--to-widevine", action="store_true")
    sp.add_argument("--set-key-id", action="append")
    sp.set_defaults(func=command_pssh)
    return parser

__all__ = ("PSSH", "Device", "DeviceTypes", "Cdm", "Key", "Session", "ClientIdentification", "DrmCertificate", "SignedDrmCertificate", "SignedMessage", "License", "LicenseRequest", "WidevinePsshData", "FileHashes", "EncryptedClientIdentification", "Exception", "TooManySessions", "InvalidSession", "InvalidInitData", "InvalidLicenseType", "InvalidLicenseMessage", "InvalidContext", "SignatureMismatch", "NoKeysLoaded")

if __name__ == "__main__":
    cli_parser = build_parser()
    cli_args = cli_parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if cli_args.debug else logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
    if cli_args.version:
        print(__version__)
        raise SystemExit(0)
    if not cli_args.cmd:
        cli_parser.print_help()
        raise SystemExit(0)
    try:
        raise SystemExit(cli_args.func(cli_args))
    except Exception as error:
        logging.getLogger("main").error(str(error))
        raise SystemExit(1)