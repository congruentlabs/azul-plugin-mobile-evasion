from io import BytesIO
import plistlib
import struct
from zipfile import ZipFile

import pytest
from azul_runner.test_utils import TestPlugin

from azul_plugin_mobile_evasion.main import AzulPluginMobileEvasion

DEX_MAGIC = b"dex\n035\x00"
MACHO_64_MAGIC = b"\xcf\xfa\xed\xfe"


class BaseMobileEvasionTest(TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMobileEvasion
    PLUGIN_TO_TEST_CONFIG = {}


@pytest.fixture(autouse=True)
def _disable_blob_cache(monkeypatch):
    monkeypatch.setenv("FILE_MANAGER_AZURE_BLOB_CACHE_ENABLED", "false")


def make_zip(entries: dict[str, bytes], *, compression=0) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def make_apk(*chunks: bytes) -> bytes:
    content = DEX_MAGIC + b"\n".join(chunks)
    return make_zip(
        {
            "AndroidManifest.xml": b"<manifest />",
            "classes.dex": content,
            "resources.arsc": b"resources",
        }
    )


def make_ipa(*chunks: bytes, info_plist: dict | None = None, plist_fmt=plistlib.FMT_XML) -> bytes:
    content = MACHO_64_MAGIC + b"\n".join(chunks)
    plist = info_plist or {}
    return make_zip(
        {
            "Payload/Test.app/Test": content,
            "Payload/Test.app/Info.plist": plistlib.dumps(plist, fmt=plist_fmt),
            "Payload/Test.app/_CodeSignature/CodeResources": b"signature",
        }
    )


# --- Android binary XML (AXML) encoder -------------------------------------------------
# Produces the compiled-manifest format that real APKs ship, so the scanner's binary-XML
# parser is exercised against genuine byte layouts rather than plain-text stand-ins.

_AXML_STRING_POOL_TYPE = 0x0001
_AXML_START_ELEMENT_TYPE = 0x0102
_AXML_END_ELEMENT_TYPE = 0x0103
_AXML_UTF8_FLAG = 1 << 8
_AXML_NO_ENTRY = 0xFFFFFFFF
_AXML_TYPE_STRING = 0x03
_AXML_TYPE_INT_DEC = 0x10


def _axml_len_u8(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    return bytes([(length >> 8) | 0x80, length & 0xFF])


class _AxmlStringPool:
    def __init__(self, utf8: bool):
        self._utf8 = utf8
        self._items: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self._items)
            self._items.append(value)
        return self._index[value]

    def _encode(self, value: str) -> bytes:
        if self._utf8:
            data = value.encode("utf-8")
            return _axml_len_u8(len(value)) + _axml_len_u8(len(data)) + data + b"\x00"
        data = value.encode("utf-16-le")
        return struct.pack("<H", len(value)) + data + b"\x00\x00"

    def build(self) -> bytes:
        encoded = b""
        offsets = []
        for value in self._items:
            offsets.append(len(encoded))
            encoded += self._encode(value)
        encoded += b"\x00" * ((-len(encoded)) % 4)
        strings_start = 28 + len(self._items) * 4
        flags = _AXML_UTF8_FLAG if self._utf8 else 0
        header = struct.pack(
            "<HHIIIIII",
            _AXML_STRING_POOL_TYPE,
            28,
            strings_start + len(encoded),
            len(self._items),
            0,
            flags,
            strings_start,
            0,
        )
        offset_table = b"".join(struct.pack("<I", offset) for offset in offsets)
        return header + offset_table + encoded


def _axml_attribute(name_index: int, raw_value: int, data_type: int, data: int) -> bytes:
    # ns, name, rawValue, then Res_value (size, res0, dataType, data).
    return struct.pack("<IIIHBBI", _AXML_NO_ENTRY, name_index, raw_value, 8, 0, data_type, data)


def _axml_start_element(name_index: int, attributes: list[bytes]) -> bytes:
    attribute_bytes = b"".join(attributes)
    node = struct.pack("<HHI", _AXML_START_ELEMENT_TYPE, 16, 16 + 20 + len(attribute_bytes))
    node += struct.pack("<II", 1, _AXML_NO_ENTRY)  # lineNumber, comment
    node += struct.pack("<II", _AXML_NO_ENTRY, name_index)  # ns, name
    node += struct.pack("<HHHHHH", 20, 20, len(attributes), 0, 0, 0)
    return node + attribute_bytes


def _axml_end_element(name_index: int) -> bytes:
    node = struct.pack("<HHI", _AXML_END_ELEMENT_TYPE, 16, 24)
    node += struct.pack("<II", 1, _AXML_NO_ENTRY)  # lineNumber, comment
    node += struct.pack("<II", _AXML_NO_ENTRY, name_index)  # ns, name
    return node


def encode_axml(
    *,
    package: str,
    version_name: str,
    min_sdk: int,
    target_sdk: int,
    permissions: list[str],
    utf8: bool = True,
) -> bytes:
    pool = _AxmlStringPool(utf8)
    manifest_name = pool.add("manifest")
    uses_sdk_name = pool.add("uses-sdk")
    uses_permission_name = pool.add("uses-permission")
    package_attr = pool.add("package")
    version_name_attr = pool.add("versionName")
    min_sdk_attr = pool.add("minSdkVersion")
    target_sdk_attr = pool.add("targetSdkVersion")
    name_attr = pool.add("name")
    package_value = pool.add(package)
    version_value = pool.add(version_name)
    permission_values = [pool.add(permission) for permission in permissions]

    nodes = _axml_start_element(
        manifest_name,
        [
            _axml_attribute(package_attr, package_value, _AXML_TYPE_STRING, package_value),
            _axml_attribute(version_name_attr, version_value, _AXML_TYPE_STRING, version_value),
        ],
    )
    nodes += _axml_end_element(manifest_name)
    nodes += _axml_start_element(
        uses_sdk_name,
        [
            _axml_attribute(min_sdk_attr, _AXML_NO_ENTRY, _AXML_TYPE_INT_DEC, min_sdk),
            _axml_attribute(target_sdk_attr, _AXML_NO_ENTRY, _AXML_TYPE_INT_DEC, target_sdk),
        ],
    )
    nodes += _axml_end_element(uses_sdk_name)
    for permission_value in permission_values:
        nodes += _axml_start_element(
            uses_permission_name,
            [_axml_attribute(name_attr, permission_value, _AXML_TYPE_STRING, permission_value)],
        )
        nodes += _axml_end_element(uses_permission_name)

    body = pool.build() + nodes
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body
