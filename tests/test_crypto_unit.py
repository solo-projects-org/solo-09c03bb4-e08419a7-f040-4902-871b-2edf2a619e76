"""加密模块与信封原语的离线单元测试（不起服务）。"""
import asyncio
import importlib
import io
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# 两个服务的包都叫 app：清掉可能已缓存的 app.* 后分别加载
for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
    del sys.modules[name]
sys.path.insert(0, str(ROOT / "api"))
crypto_stream = importlib.import_module("app.crypto_stream")
export_package = importlib.import_module("app.export_package")
sys.path.remove(str(ROOT / "api"))
for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
    del sys.modules[name]
sys.path.insert(0, str(ROOT / "keystore"))
crypto_envelope = importlib.import_module("app.crypto_envelope")
sys.path.remove(str(ROOT / "keystore"))
for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
    del sys.modules[name]
# 接收方独立解包工具（tools/ 下的自包含脚本）
sys.path.insert(0, str(ROOT / "tools"))
msxp_unpack = importlib.import_module("msxp_unpack")
sys.path.remove(str(ROOT / "tools"))

CHUNK_SIZE = crypto_stream.CHUNK_SIZE
HEADER_LEN = crypto_stream.HEADER_LEN
IntegrityError = crypto_stream.IntegrityError
decrypt_stream = crypto_stream.decrypt_stream
encrypt_stream = crypto_stream.encrypt_stream
ENVELOPE_LEN = crypto_envelope.ENVELOPE_LEN
new_data_key = crypto_envelope.new_data_key
unwrap_dek = crypto_envelope.unwrap_dek
wrap_dek = crypto_envelope.wrap_dek


async def _roundtrip(data: bytes, dek: bytes):
    out = bytearray()

    async def write(chunk: bytes):
        out.extend(chunk)

    async def plain_chunks():
        for i in range(0, len(data), 777):
            yield data[i:i + 777]

    stats = await encrypt_stream(plain_chunks(), dek, write)
    assert stats["plain_size"] == len(data)
    blob = bytes(out)

    async def cipher_chunks():
        for i in range(0, len(blob), 999):
            yield blob[i:i + 999]

    got = await _collect(decrypt_stream(cipher_chunks(), dek, stats["sha256"]))
    return blob, got, stats


async def _collect(agen):
    out = bytearray()
    async for c in agen:
        out.extend(c)
    return bytes(out)


def test_stream_roundtrip_sizes():
    for size in (0, 1, 1024, CHUNK_SIZE - 1, CHUNK_SIZE,
                 CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 5):
        dek = os.urandom(32)
        data = os.urandom(size)
        blob, got, stats = asyncio.run(_roundtrip(data, dek))
        assert got == data
        n_full, tail = divmod(size, CHUNK_SIZE)
        n_frames = n_full + (1 if tail else 0)
        # 每帧开销 = 4 长度 + 12 nonce + 16 GCM tag；另有文件头与结束帧
        expect = HEADER_LEN + 4 + n_frames * (4 + 12 + 16) + size
        assert stats["enc_size"] == len(blob) == expect


def test_tamper_and_wrong_dek_detected():
    dek = os.urandom(32)
    blob, _, _ = asyncio.run(_roundtrip(b"x" * 5000, dek))
    bad = bytearray(blob)
    bad[HEADER_LEN + 10] ^= 0x01

    async def chunks(buf):
        yield buf

    with pytest.raises(IntegrityError):
        asyncio.run(_collect(decrypt_stream(chunks(bytes(bad)), dek)))
    with pytest.raises(IntegrityError):
        asyncio.run(_collect(decrypt_stream(chunks(blob), os.urandom(32))))


def test_envelope_wrap_unwrap_and_aad():
    mk = os.urandom(32)
    dek = new_data_key()
    env = wrap_dek(mk, dek, b"image-1")
    assert len(env) == ENVELOPE_LEN
    assert unwrap_dek(mk, env, b"image-1") == dek
    with pytest.raises(Exception):
        unwrap_dek(mk, env, b"other-aad")            # AAD 不匹配
    with pytest.raises(Exception):
        unwrap_dek(os.urandom(32), env, b"image-1")  # 错误主密钥


# --------------------------------------------------------------------------
# 交接包（MSXP）离线闭环：API 侧构造 -> 接收方工具独立解包
# --------------------------------------------------------------------------
def _make_package(image_id: str, payload: bytes, dek: bytes,
                  recipient_pub: bytes) -> bytes:
    """离线构造一个完整交接包：MSEF 密文 + MSXP 头。"""
    out = bytearray()

    async def write(chunk: bytes):
        out.extend(chunk)

    async def chunks():
        yield payload

    stats = asyncio.run(
        crypto_stream.encrypt_stream(chunks(), dek, write))
    header = export_package.build_header(
        image_id, stats["enc_size"], stats["sha256"], recipient_pub, dek)
    return export_package.package_prefix(header) + bytes(out)


def test_export_package_offline_roundtrip():
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    priv = X25519PrivateKey.generate()
    payload = os.urandom(1024 * 1024 + 777)
    dek = os.urandom(32)
    package = _make_package("img-offline", payload, dek,
                            priv.public_key().public_bytes_raw())
    out = io.BytesIO()
    header = msxp_unpack.unpack_package(
        io.BytesIO(package), priv.private_bytes_raw(), out)
    assert header["image_id"] == "img-offline"
    assert out.getvalue() == payload
    # 错私钥解不开
    other = X25519PrivateKey.generate()
    with pytest.raises(msxp_unpack.PackageError):
        msxp_unpack.unpack_package(io.BytesIO(package),
                                   other.private_bytes_raw(), io.BytesIO())
    # 尾部多余字节也算污染
    with pytest.raises(msxp_unpack.PackageError):
        msxp_unpack.unpack_package(io.BytesIO(package + b"x"),
                                   priv.private_bytes_raw(), io.BytesIO())
    # 截断必失败
    with pytest.raises(msxp_unpack.PackageError):
        msxp_unpack.unpack_package(io.BytesIO(package[:-1]),
                                   priv.private_bytes_raw(), io.BytesIO())


def test_parse_recipient_public_key_variants():
    import base64
    raw = os.urandom(32)
    assert export_package.parse_recipient_public_key(raw.hex()) == raw
    assert export_package.parse_recipient_public_key(
        base64.b64encode(raw).decode()) == raw
    assert export_package.parse_recipient_public_key(
        base64.urlsafe_b64encode(raw).decode()) == raw
    for bad in ("", "zz", "00" * 31, "00" * 33, None):
        with pytest.raises(export_package.ExportPackageError):
            export_package.parse_recipient_public_key(bad)


def test_package_prefix_layout_and_bounds():
    header = b'{"a":1}'
    prefix = export_package.package_prefix(header)
    assert prefix[:4] == b"MSXP" and prefix[4] == 1
    assert int.from_bytes(prefix[5:9], "big") == len(header)
    assert prefix[9:] == header
    with pytest.raises(export_package.ExportPackageError):
        export_package.package_prefix(b"x" * (17 * 1024))
