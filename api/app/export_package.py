"""加密交接包（MSXP）：原片密文原样装包 + 一次性协商密钥包裹该件 DEK。

用途：向无法连接本库的合作方交接已入仓原片。包内密文逐字节等于仓内
blob（不重加密、不解密）；DEK 用"一次性临时 X25519 密钥对 + 接收方公钥"
协商出的包裹密钥封装，接收方凭私钥即可独立解包、逐帧验签、核对摘要，
全程无需本库主密钥或密钥服务在线。

包布局（多字节整数均为大端）：
  magic(4)      = b"MSXP"
  version(1)    = 0x01
  header_len(4) header JSON 的字节数
  header        UTF-8 JSON（字段见 build_header 注释）
  payload       原片密文（.msef 字节流，恰好 header["enc_size"] 字节）

完整性语义（接收方据此判定"包是否完整"，不依赖 HTTP 状态）：
  * header 声明密文长度 enc_size 与原片明文 SHA-256；
  * payload 为 MSEF 分帧密文，每帧 AES-256-GCM 独立验签，且以结束帧收尾；
  * 传输中断/截断 => payload 字节数不足或缺结束帧 => 解包失败；
  * 篡改任何密文字节 => 对应帧 GCM 验签失败 => 解包失败；
  * 密钥信封 AAD 绑定 image_id，信封无法被搬到其他编号的包中重放。
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PACKAGE_MAGIC = b"MSXP"
PACKAGE_VERSION = 1
PACKAGE_PREFIX_LEN = len(PACKAGE_MAGIC) + 1 + 4  # magic + version + header_len
PACKAGE_FORMAT = "MSXP1"
CIPHER_FORMAT = "MSEF1"          # 内嵌 payload 即仓内 .msef 密文格式
KEM_ID = "X25519-HKDF-SHA256-AES256GCM"
HKDF_INFO = b"msxp-dek-wrap-v1"
WRAP_NONCE_LEN = 12
DEK_LEN = 32

MAX_HEADER_BYTES = 16 * 1024     # 防御性上限：header 只含固定字段


class ExportPackageError(Exception):
    """交接包构造/解析中的确定性错误。"""


def parse_recipient_public_key(text: str) -> bytes:
    """解析接收方 X25519 公钥：接受 64 位 hex 或 base64（标准/urlsafe）。"""
    raw: bytes | None = None
    text = (text or "").strip()
    try:
        candidate = bytes.fromhex(text)
        if len(candidate) == 32:
            raw = candidate
    except ValueError:
        pass
    if raw is None:
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                candidate = decoder(text)
            except (ValueError, binascii.Error):
                continue
            if len(candidate) == 32:
                raw = candidate
                break
    if raw is None:
        raise ExportPackageError(
            "recipient_public_key must be a 32-byte X25519 key "
            "(hex or base64)")
    # 交给 cryptography 做一次格式校验（长度/曲线点编码）
    try:
        X25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ExportPackageError(f"invalid X25519 public key: {exc}") from exc
    return raw


def _derive_wrap_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=HKDF_INFO).derive(shared_secret)


def build_header(image_id: str, enc_size: int, sha256: str,
                 recipient_public_key: bytes, dek: bytes) -> bytes:
    """用一次性临时密钥对把 DEK 封装给接收方，返回 header JSON 字节。

    每次导出生成全新的临时 X25519 密钥对（一次性协商密钥）：
      shared   = ECDH(ephemeral_private, recipient_public)
      wrap_key = HKDF-SHA256(shared, info=HKDF_INFO)
      envelope = nonce || AES-256-GCM(wrap_key, DEK, aad=image_id) || tag
    临时私钥不出本函数；调用方负责在返回后丢弃明文 DEK 引用。

    header 字段：
      format/cipher_format/kem  格式与算法标识（接收方据此选择解包逻辑）
      image_id                  原片编号（同时是 DEK 信封的 AAD）
      enc_size                  payload 密文字节数（完整性核对）
      sha256                    原片明文 SHA-256（复核摘要）
      ephemeral_public_key      一次性临时公钥（hex）
      dek_envelope              包裹后的 DEK（hex，60 字节）
      created_at                导出时间戳（信息性）
    """
    if len(dek) != DEK_LEN:
        raise ExportPackageError("dek must be 32 bytes")
    ephemeral = X25519PrivateKey.generate()
    peer = X25519PublicKey.from_public_bytes(recipient_public_key)
    shared = ephemeral.exchange(peer)
    wrap_key = _derive_wrap_key(shared)
    nonce = os.urandom(WRAP_NONCE_LEN)
    envelope = nonce + AESGCM(wrap_key).encrypt(nonce, dek, image_id.encode())
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    header = {
        "format": PACKAGE_FORMAT,
        "cipher_format": CIPHER_FORMAT,
        "kem": KEM_ID,
        "image_id": image_id,
        "enc_size": enc_size,
        "sha256": sha256,
        "ephemeral_public_key": ephemeral_public.hex(),
        "dek_envelope": envelope.hex(),
        "created_at": time.time(),
    }
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def package_prefix(header_bytes: bytes) -> bytes:
    """包前缀：magic + version + header_len + header。"""
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise ExportPackageError("package header too large")
    return (PACKAGE_MAGIC + bytes([PACKAGE_VERSION])
            + len(header_bytes).to_bytes(4, "big") + header_bytes)
