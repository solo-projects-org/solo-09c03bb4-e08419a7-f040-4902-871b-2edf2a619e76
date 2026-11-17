"""T13：加密交接包导出（MSXP）端到端测试。

覆盖：
  E1  导出-独立解包往返：包结构、响应头、逐字节一致、摘要核对
  E2  包内无明文（密文原样装包）
  E3  错误私钥 / 篡改密文 / 篡改摘要 / 截断包 -> 接收方判定不完整
  E4  轮换改包与导出交错：导出的 DEK 始终对应该份密文
  E5  轮换完成（旧 MK 销毁）后导出正常
  E6  密钥服务不可用 -> 503，接收方拿不到包；恢复后导出恢复
  E7  密文缺失/尺寸不符 -> 410/500，不交付
  E8  编号不存在/未就绪/公钥非法 -> 404/409/400
  E9  导出不在磁盘产生任何新文件（明文不落盘）
  E10 行信封指向已销毁 MK 且未迁移 -> 如实 410，不交付可疑包
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from conftest import TOKEN, _download, _key_headers, _upload, _wait_rotation

ROOT = Path(__file__).resolve().parents[1]
UNPACK_TOOL = ROOT / "tools" / "msxp_unpack.py"


def _new_recipient_keypair() -> tuple[str, str]:
    """返回 (私钥 hex, 公钥 hex)。"""
    priv = X25519PrivateKey.generate()
    return (priv.private_bytes_raw().hex(),
            priv.public_key().public_bytes_raw().hex())


def _export(client: httpx.Client, image_id: str, pub: str) -> httpx.Response:
    return client.post(f"/images/{image_id}/export",
                       json={"recipient_public_key": pub})


def _run_unpack(package_path: Path, priv_hex: str, out_path: Path,
                tmp_path: Path) -> subprocess.CompletedProcess:
    key_file = tmp_path / (out_path.name + ".sk")
    key_file.write_text(priv_hex)
    return subprocess.run(
        [sys.executable, "-I", str(UNPACK_TOOL),
         "--key", str(key_file), "--package", str(package_path),
         "--out", str(out_path)],
        capture_output=True, text=True, timeout=60)


def _parse_header(package: bytes) -> dict:
    assert package[:4] == b"MSXP" and package[4] == 1
    header_len = int.from_bytes(package[5:9], "big")
    return json.loads(package[9:9 + header_len])


def test_export_roundtrip_independent_unpack(stack, tmp_path):
    client = stack["client"]
    payload = os.urandom(2 * 1024 * 1024 + 12345)  # 跨多帧
    assert _upload(client, payload, image_id="exp-1").status_code == 201
    priv_hex, pub_hex = _new_recipient_keypair()

    r = _export(client, "exp-1", pub_hex)
    assert r.status_code == 200, r.text
    package = r.content
    # 响应头自描述：Content-Length 精确（传输中断可被客户端察觉）
    assert int(r.headers["content-length"]) == len(package)
    assert r.headers["x-sha256"]
    assert r.headers["content-disposition"].endswith('filename="exp-1.msxp"')

    header = _parse_header(package)
    assert header["image_id"] == "exp-1"
    assert header["format"] == "MSXP1" and header["cipher_format"] == "MSEF1"
    assert header["kem"] == "X25519-HKDF-SHA256-AES256GCM"
    assert header["enc_size"] == len(package) - 9 - len(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    meta = client.get("/images/exp-1/meta").json()
    assert header["sha256"] == meta["sha256"]
    assert header["enc_size"] == meta["enc_size"]
    # 密文原样装包：包内 payload 与仓内 blob 逐字节一致
    header_len = int.from_bytes(package[5:9], "big")
    blob_bytes = (stack["blob_dir"] / "exp-1.msef").read_bytes()
    assert package[9 + header_len:] == blob_bytes

    pkg_path = tmp_path / "exp-1.msxp"
    pkg_path.write_bytes(package)
    out_path = tmp_path / "recovered.bin"
    proc = _run_unpack(pkg_path, priv_hex, out_path, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "OK image_id=exp-1" in proc.stderr
    assert out_path.read_bytes() == payload

    # base64 公钥同样接受
    import base64
    r2 = _export(client, "exp-1",
                 base64.b64encode(bytes.fromhex(pub_hex)).decode())
    assert r2.status_code == 200
    # 每次导出使用不同的一次性临时公钥（协商密钥一次性）
    assert _parse_header(r2.content)["ephemeral_public_key"] != \
        header["ephemeral_public_key"]


def test_export_package_contains_no_plaintext(stack):
    client = stack["client"]
    marker = b"EXPORT-PLAINTEXT-MARKER-" + os.urandom(1024)
    _upload(client, marker * 32, image_id="exp-noleak")
    _, pub_hex = _new_recipient_keypair()
    package = _export(client, "exp-noleak", pub_hex).content
    assert marker not in package  # 密文原样装包，明文不进包


def test_export_wrong_key_tamper_and_truncation_rejected(stack, tmp_path):
    client = stack["client"]
    payload = b"handoff-payload" * 5000
    _upload(client, payload, image_id="exp-sec")
    priv_hex, pub_hex = _new_recipient_keypair()
    package = _export(client, "exp-sec", pub_hex).content
    pkg = tmp_path / "case.msxp"

    # 1) 错误私钥 -> 解信封失败
    wrong_priv, _ = _new_recipient_keypair()
    pkg.write_bytes(package)
    out = tmp_path / "wrong.bin"
    proc = _run_unpack(pkg, wrong_priv, out, tmp_path)
    assert proc.returncode == 1 and not out.exists()
    assert "INCOMPLETE OR INVALID PACKAGE" in proc.stderr

    # 2) 篡改密文一字节 -> GCM 验签失败
    header_len = int.from_bytes(package[5:9], "big")
    flip_at = 9 + header_len + 40
    bad = bytearray(package)
    bad[flip_at] ^= 0x01
    pkg.write_bytes(bytes(bad))
    out = tmp_path / "tampered.bin"
    proc = _run_unpack(pkg, priv_hex, out, tmp_path)
    assert proc.returncode == 1 and not out.exists()

    # 3) 篡改 header 中的 sha256（等长替换）-> 摘要核对失败
    header = _parse_header(package)
    bad_sha = ("0" if header["sha256"][0] != "0" else "1") + header["sha256"][1:]
    bad_pkg = package.replace(header["sha256"].encode(),
                              bad_sha.encode(), 1)
    assert len(bad_pkg) == len(package)
    pkg.write_bytes(bad_pkg)
    out = tmp_path / "badsha.bin"
    proc = _run_unpack(pkg, priv_hex, out, tmp_path)
    assert proc.returncode == 1 and not out.exists()

    # 4) 传输中断（截尾）-> 缺结束帧/长度不足，判定不完整
    pkg.write_bytes(package[:-37])
    out = tmp_path / "trunc.bin"
    proc = _run_unpack(pkg, priv_hex, out, tmp_path)
    assert proc.returncode == 1 and not out.exists()

    # 5) 正常解包仍成功（对照）
    pkg.write_bytes(package)
    out = tmp_path / "ok.bin"
    proc = _run_unpack(pkg, priv_hex, out, tmp_path)
    assert proc.returncode == 0 and out.read_bytes() == payload


def test_export_interleaved_with_rotation(stack, tmp_path):
    """轮换改包与导出交错：慢密钥服务下，轮换进行中导出的每件原片，
    接收方都能用包内信封解出与密文对应的 DEK，逐字节复核通过。"""
    client = stack["client"]
    payloads = {f"irl-{i}": os.urandom(300_000 + i) for i in range(3)}
    for image_id, data in payloads.items():
        assert _upload(client, data, image_id=image_id).status_code == 201
    priv_hex, pub_hex = _new_recipient_keypair()

    # 慢密钥服务拉长迁移/销毁窗口，使导出必然与 rewrap/destroy 交错
    env = dict(stack["keys"]._env)
    env["KEY_OP_DELAY"] = "0.3"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()

    job = client.post("/rotations", json={"confirm": True}).json()
    results = {}
    for round_ in range(2):  # 迁移窗口内反复导出，覆盖改包前后
        for image_id in payloads:
            r = _export(client, image_id, pub_hex)
            assert r.status_code == 200, (image_id, r.text)
            results[(round_, image_id)] = r.content
    final = _wait_rotation(client, job["job_id"], timeout=120)
    assert final["state"] == "completed", final
    # 旧 MK 销毁后再导出一轮
    for image_id in payloads:
        r = _export(client, image_id, pub_hex)
        assert r.status_code == 200
        results[("post", image_id)] = r.content

    for (round_, image_id), package in results.items():
        pkg = tmp_path / f"{image_id}-{round_}.msxp"
        pkg.write_bytes(package)
        out = tmp_path / f"{image_id}-{round_}.bin"
        proc = _run_unpack(pkg, priv_hex, out, tmp_path)
        assert proc.returncode == 0, (round_, image_id, proc.stderr)
        assert out.read_bytes() == payloads[image_id]


def test_export_after_rotation_completed(stack, tmp_path):
    client = stack["client"]
    payload = b"post-rotation-export" * 2000
    _upload(client, payload, image_id="exp-post")
    job = client.post("/rotations", json={"confirm": True}).json()
    assert _wait_rotation(client, job["job_id"])["state"] == "completed"
    priv_hex, pub_hex = _new_recipient_keypair()
    r = _export(client, "exp-post", pub_hex)
    assert r.status_code == 200
    pkg = tmp_path / "post.msxp"
    pkg.write_bytes(r.content)
    out = tmp_path / "post.bin"
    proc = _run_unpack(pkg, priv_hex, out, tmp_path)
    assert proc.returncode == 0 and out.read_bytes() == payload


def test_export_key_service_unavailable_no_partial_package(stack):
    client = stack["client"]
    _upload(client, b"ks-down-case", image_id="exp-ksdown")
    _, pub_hex = _new_recipient_keypair()
    stack["keys"].stop()  # 密钥服务不可用
    try:
        r = _export(client, "exp-ksdown", pub_hex)
        # 必须确定性失败（5xx），绝不允许 200 流出半个包
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "key_service_unreachable"
    finally:
        stack["keys"].start()
    r = _export(client, "exp-ksdown", pub_hex)  # 恢复后导出照常
    assert r.status_code == 200


def test_export_missing_or_mismatched_blob(stack):
    client = stack["client"]
    _upload(client, b"blob-gone", image_id="exp-gone")
    _, pub_hex = _new_recipient_keypair()
    blob = stack["blob_dir"] / "exp-gone.msef"
    data = blob.read_bytes()
    blob.unlink()
    r = _export(client, "exp-gone", pub_hex)
    assert r.status_code == 410
    # 密文被截断（尺寸与元数据不符）-> 500，不交付
    blob.write_bytes(data[: len(data) // 2])
    r = _export(client, "exp-gone", pub_hex)
    assert r.status_code == 500
    assert r.json()["detail"]["code"] == "ciphertext_size_mismatch"


def test_export_rejects_unknown_not_ready_and_bad_key(stack):
    client = stack["client"]
    _, pub_hex = _new_recipient_keypair()
    assert _export(client, "no-such-image", pub_hex).status_code == 404
    # failed 行不可导出
    import sqlite3
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    mk = client.get("/keys/status").json()["current_key_id"]
    conn.execute(
        "INSERT INTO images (image_id, status, master_key_id, wrapped_dek, "
        "blob_path, created_at) VALUES ('exp-failed','failed',?,?,?,?)",
        (mk, "00" * 64, str(stack["blob_dir"] / "exp-failed.msef"),
         time.time()))
    conn.commit()
    conn.close()
    assert _export(client, "exp-failed", pub_hex).status_code == 409
    # 非法公钥
    _upload(client, b"badkey-target", image_id="exp-badkey")
    assert _export(client, "exp-badkey", "not-a-key").status_code == 400
    assert _export(client, "exp-badkey", "00" * 16).status_code == 400


def test_export_writes_no_files(stack):
    client = stack["client"]
    _upload(client, b"no-disk-write" * 100, image_id="exp-nodisk")
    _, pub_hex = _new_recipient_keypair()
    before = {p for p in stack["data_dir"].rglob("*") if p.is_file()}
    r = _export(client, "exp-nodisk", pub_hex)
    assert r.status_code == 200
    after = {p for p in stack["data_dir"].rglob("*") if p.is_file()}
    assert before == after  # 导出纯流式，不产生任何落盘文件


def test_export_row_bound_to_destroyed_key_fails_cleanly(stack):
    """行信封仍指向已销毁 MK（绕过轮换迁移的极端残留）：
    导出如实 410，绝不交付无法核实的包。"""
    client, kc = stack["client"], stack["key_client"]
    _upload(client, b"orphan-envelope", image_id="exp-orphan")
    _, pub_hex = _new_recipient_keypair()
    # 绕过 API 轮换：直接在密钥服务轮换并销毁旧 MK，DB 行保持旧信封
    old_key = client.get("/images/exp-orphan/meta").json()["master_key_id"]
    kc.post("/internal/master/rotate", headers=_key_headers())
    r = kc.post("/internal/master/destroy", json={"key_id": old_key},
                headers=_key_headers())
    assert r.status_code == 200
    resp = _export(client, "exp-orphan", pub_hex)
    assert resp.status_code == 410
    assert resp.json()["detail"]["code"] == "key_destroyed"
