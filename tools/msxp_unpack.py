#!/usr/bin/env python3
"""MSXP 加密交接包独立解包工具（接收方侧）。

接收方无需连接交付方的仓库、密钥服务或主密钥；凭自己的 X25519 私钥即可
独立解包、逐帧验签并核对摘要。仅依赖 `cryptography` 库。

用法：
    python3 msxp_unpack.py --key recipient_private.hex \
        --package img-xxx.msxp --out recovered.bin

    --key       接收方 X25519 私钥文件（64 个 hex 字符，32 字节）
    --package   交接包文件路径（或 "-" 读标准输入）
    --out       明文输出路径（或 "-" 写标准输出；校验全部通过才落位）

完整性判定（以下全部通过才认为包完整，否则删除部分输出并非零退出）：
  1. 包头结构完整：magic/version/header_len/header JSON；
  2. 私钥可解开 DEK 信封（X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM，
     AAD 绑定包内 image_id）；
  3. payload 为 MSEF 分帧密文：逐帧 AES-256-GCM 验签、帧计数器 nonce 匹配、
     结束帧存在；
  4. payload 字节数恰好等于 header.enc_size（无截断、无多余字节）；
  5. 明文 SHA-256 等于 header.sha256。

防"误认完整"设计：明文先写入 <out>.part 临时文件，全部校验通过后才
rename 为最终路径；任何失败都会删除临时文件。因此最终路径存在即代表
该包通过了全部校验。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---- 包格式常量（与交付方 export_package 对应，独立维护） -----------------
PACKAGE_MAGIC = b"MSXP"
PACKAGE_VERSION = 1
PACKAGE_FORMAT = "MSXP1"
CIPHER_FORMAT = "MSEF1"
KEM_ID = "X25519-HKDF-SHA256-AES256GCM"
HKDF_INFO = b"msxp-dek-wrap-v1"
MAX_HEADER_BYTES = 16 * 1024

# ---- MSEF 密文帧格式常量（与交付方 crypto_stream 对应，独立维护） ---------
MSEF_MAGIC = b"MSEF"
MSEF_VERSION = 1
MSEF_SALT_LEN = 16
MSEF_NONCE_PREFIX_LEN = 8
MSEF_HEADER_LEN = len(MSEF_MAGIC) + 1 + MSEF_SALT_LEN

READ_CHUNK = 1024 * 1024


class PackageError(Exception):
    """包不完整/被篡改/密钥不匹配——接收方应判定本次交接失败。"""


class _Reader:
    """按精确长度从文件对象读取（屏蔽短读），越界即报截断。"""

    def __init__(self, fh, limit: int | None = None):
        self._fh = fh
        self._remaining = limit  # None 表示不限

    def read_exact(self, n: int, what: str) -> bytes:
        if self._remaining is not None and n > self._remaining:
            raise PackageError(f"truncated package: {what} exceeds payload")
        out = bytearray()
        while len(out) < n:
            want = n - len(out)
            if self._remaining is not None:
                want = min(want, self._remaining)
            chunk = self._fh.read(want)
            if not chunk:
                raise PackageError(f"truncated package: missing {what}")
            out.extend(chunk)
            if self._remaining is not None:
                self._remaining -= len(chunk)
        return bytes(out)

    @property
    def remaining(self) -> int | None:
        return self._remaining


def _unwrap_dek(header: dict, private_key_bytes: bytes) -> bytes:
    if header.get("kem") != KEM_ID:
        raise PackageError(f"unsupported KEM: {header.get('kem')!r}")
    try:
        eph_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(header["ephemeral_public_key"]))
        envelope = bytes.fromhex(header["dek_envelope"])
    except (KeyError, ValueError) as exc:
        raise PackageError(f"malformed key envelope fields: {exc}") from exc
    shared = X25519PrivateKey.from_private_bytes(private_key_bytes).exchange(
        eph_pub)
    wrap_key = HKDF(algorithm=SHA256(), length=32, salt=None,
                    info=HKDF_INFO).derive(shared)
    nonce, ct = envelope[:12], envelope[12:]
    try:
        return AESGCM(wrap_key).decrypt(nonce, ct,
                                        header["image_id"].encode())
    except Exception as exc:
        raise PackageError(
            "DEK unwrap failed: wrong recipient private key or "
            "tampered envelope") from exc


def _decrypt_payload(reader: _Reader, dek: bytes, expected_sha256: str,
                     out_fh) -> int:
    """逐帧验签解密 MSEF payload，写明文到 out_fh；返回密文字节数。"""
    consumed = 0
    hdr = reader.read_exact(MSEF_HEADER_LEN, "ciphertext header")
    consumed += MSEF_HEADER_LEN
    if hdr[:4] != MSEF_MAGIC or hdr[4] != MSEF_VERSION:
        raise PackageError("bad MSEF ciphertext header")
    salt = hdr[5:5 + MSEF_SALT_LEN]
    aes = AESGCM(dek)
    digest = hashlib.sha256()
    counter = 0
    while True:
        len_bytes = reader.read_exact(4, "frame length")
        consumed += 4
        frame_len = int.from_bytes(len_bytes, "big")
        if frame_len == 0:
            break  # 结束帧
        nonce = reader.read_exact(12, "frame nonce")
        frame = reader.read_exact(frame_len, "frame body")
        consumed += 12 + frame_len
        expected_nonce = (salt[:MSEF_NONCE_PREFIX_LEN]
                          + counter.to_bytes(4, "big"))
        if nonce != expected_nonce:
            raise PackageError("frame nonce mismatch (reordered/tampered)")
        try:
            plain = aes.decrypt(nonce, frame, None)
        except Exception as exc:
            raise PackageError(
                f"GCM authentication failed at frame {counter}") from exc
        digest.update(plain)
        out_fh.write(plain)
        counter += 1
    if digest.hexdigest() != expected_sha256:
        raise PackageError("plaintext sha256 mismatch after decryption")
    return consumed


def unpack_package(package_fh, private_key_bytes: bytes, out_fh) -> dict:
    """解包并全量校验；任何一步失败抛 PackageError。返回 header。"""
    reader = _Reader(package_fh)
    magic = reader.read_exact(4, "package magic")
    if magic != PACKAGE_MAGIC:
        raise PackageError("not an MSXP package (bad magic)")
    version = reader.read_exact(1, "package version")[0]
    if version != PACKAGE_VERSION:
        raise PackageError(f"unsupported package version {version}")
    header_len = int.from_bytes(reader.read_exact(4, "header length"), "big")
    if header_len > MAX_HEADER_BYTES:
        raise PackageError("package header too large")
    try:
        header = json.loads(reader.read_exact(header_len, "package header"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"malformed package header: {exc}") from exc
    if header.get("format") != PACKAGE_FORMAT:
        raise PackageError(f"unsupported package format "
                           f"{header.get('format')!r}")
    if header.get("cipher_format") != CIPHER_FORMAT:
        raise PackageError(f"unsupported cipher format "
                           f"{header.get('cipher_format')!r}")
    enc_size = header.get("enc_size")
    if not isinstance(enc_size, int) or enc_size < 0:
        raise PackageError("header enc_size missing/invalid")

    dek = _unwrap_dek(header, private_key_bytes)
    try:
        payload_reader = _Reader(package_fh, limit=enc_size)
        consumed = _decrypt_payload(payload_reader, dek,
                                    header.get("sha256") or "", out_fh)
    finally:
        del dek
    if consumed != enc_size:
        raise PackageError(f"payload size mismatch: consumed {consumed} != "
                           f"declared {enc_size}")
    # 包必须恰好结束：多一个字节都算被污染
    extra = package_fh.read(1)
    if extra:
        raise PackageError("trailing bytes after payload")
    return header


def _load_private_key(path: str) -> bytes:
    text = open(path, "r", encoding="ascii").read().strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise PackageError("private key file must contain 64 hex chars") from exc
    if len(raw) != 32:
        raise PackageError("private key must be 32 bytes")
    return raw


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MSXP 加密交接包独立解包工具")
    ap.add_argument("--key", required=True, help="接收方 X25519 私钥 hex 文件")
    ap.add_argument("--package", required=True, help="交接包路径（- 为 stdin）")
    ap.add_argument("--out", required=True, help="明文输出路径（- 为 stdout）")
    args = ap.parse_args(argv)

    try:
        private_key = _load_private_key(args.key)
    except (PackageError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    package_fh = (sys.stdin.buffer if args.package == "-"
                  else open(args.package, "rb"))
    # 先写临时文件，全部校验通过再落位，杜绝"部分明文被当成完整结果"
    if args.out == "-":
        out_path, tmp_path = None, None
        out_fh = sys.stdout.buffer
    else:
        out_path = args.out
        tmp_path = args.out + ".part"
        out_fh = open(tmp_path, "wb")
    try:
        header = unpack_package(package_fh, private_key, out_fh)
    except (PackageError, OSError) as exc:
        if tmp_path:
            out_fh.close()
            os.unlink(tmp_path)
        print(f"INCOMPLETE OR INVALID PACKAGE: {exc}", file=sys.stderr)
        return 1
    finally:
        if package_fh is not sys.stdin.buffer:
            package_fh.close()
    if tmp_path:
        out_fh.close()
        os.replace(tmp_path, out_path)
    print(f"OK image_id={header['image_id']} sha256={header['sha256']} "
          f"enc_size={header['enc_size']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
