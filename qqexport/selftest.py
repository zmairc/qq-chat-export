"""离线自检：不读真实 QQ 数据、不联网、不需要第三方库。

自己造一个「1024 字节头 + 两张加密页」的库，再走项目里的探测与解密代码，
看能不能原样还原。`python -m qqexport.selftest` 就是这个。

测试用的 AES **加密**实现只存在于这里（ctypes 调 Windows CNG）；
生产代码只有解密路径。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import os
import platform
import shutil
import struct
import sys
import traceback

from . import qq
from .cng_aes import AesCbc, AesEcb

BLOCK = 16


class Fail(AssertionError):
    pass


def _check(cond, msg):
    if not cond:
        raise Fail(msg)


class _Enc:
    """只给自检用的 AES 加密器（Windows CNG，BCryptEncrypt）。"""

    def __init__(self, key: bytes, mode: str = "CBC"):
        b = ctypes.WinDLL("bcrypt")
        self._b = b
        b.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
        b.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p), wt.LPCWSTR, wt.LPCWSTR, wt.ULONG]
        b.BCryptSetProperty.restype = ctypes.c_long
        b.BCryptSetProperty.argtypes = [
            ctypes.c_void_p, wt.LPCWSTR, ctypes.c_char_p, wt.ULONG, wt.ULONG]
        b.BCryptGenerateSymmetricKey.restype = ctypes.c_long
        b.BCryptGenerateSymmetricKey.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            wt.ULONG, ctypes.c_char_p, wt.ULONG, wt.ULONG]
        b.BCryptEncrypt.restype = ctypes.c_long
        b.BCryptEncrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, wt.ULONG, ctypes.c_void_p,
            ctypes.c_void_p, wt.ULONG, ctypes.c_char_p, wt.ULONG,
            ctypes.POINTER(wt.ULONG), wt.ULONG]

        alg = ctypes.c_void_p()
        st = b.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0)
        if st:
            raise Fail(f"BCryptOpenAlgorithmProvider 失败 0x{st & 0xFFFFFFFF:08x}")
        m = f"ChainingMode{mode}".encode("utf-16-le")
        st = b.BCryptSetProperty(alg, "ChainingMode", m, len(m), 0)
        if st:
            raise Fail(f"BCryptSetProperty({mode}) 失败 0x{st & 0xFFFFFFFF:08x}")
        hkey = ctypes.c_void_p()
        st = b.BCryptGenerateSymmetricKey(alg, ctypes.byref(hkey), None, 0, key, len(key), 0)
        if st:
            raise Fail(f"BCryptGenerateSymmetricKey 失败 0x{st & 0xFFFFFFFF:08x}")
        self._alg, self._hkey = alg, hkey

    def encrypt(self, data: bytes, iv: bytes | None = None) -> bytes:
        if len(data) % BLOCK:
            raise Fail(f"待加密数据不是 16 的整数倍（{len(data)} 字节）")
        out = ctypes.create_string_buffer(len(data))
        n = wt.ULONG(0)
        iv_buf = ctypes.create_string_buffer(bytes(iv), BLOCK) if iv else None
        st = self._b.BCryptEncrypt(
            self._hkey, data, len(data), None,
            ctypes.cast(iv_buf, ctypes.c_void_p) if iv_buf else None,
            BLOCK if iv_buf else 0, out, len(data), ctypes.byref(n), 0)
        if st:
            raise Fail(f"BCryptEncrypt 失败 0x{st & 0xFFFFFFFF:08x}")
        return out.raw[:n.value]


# ------------------------------------------------------------ 1. AES 回环

def check_aes() -> str:
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    plain = bytes((i * 7 + 5) % 256 for i in range(64))
    ct = _Enc(key, "CBC").encrypt(plain, iv)
    _check(AesCbc(key).decrypt(ct, iv) == plain, "CBC 解密与加密对不上")
    ct2 = _Enc(key, "ECB").encrypt(plain)
    _check(AesEcb(key).decrypt(ct2) == plain, "ECB 解密与加密对不上")
    return "AES（CNG 加密 ↔ 项目解密）"


# --------------------------------------------------- 2. QQ 库结构与解密

def check_qq_roundtrip() -> str:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "work", "tmp"))
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, "selftest_nt_msg.db")
    out = os.path.join(root, "selftest_nt_msg_plain.db")

    p = qq.PARAM_SETS[0]
    passphrase = b"0123456789abcdef"
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    enc_key, mac_key = qq.derive(passphrase, salt, p)
    enc = _Enc(enc_key, "CBC")
    ct1 = qq.PAGE_SZ - qq.SALT_SZ - p.reserve
    ctn = qq.PAGE_SZ - p.reserve
    pad_len = p.reserve - 16 - p.mac_len

    def seal(page_plain: bytes, pgno: int, first: bool) -> bytes:
        iv = bytes((pgno * 29 + i) % 256 for i in range(16))
        ct_len = ct1 if first else ctn
        body = page_plain[qq.SALT_SZ: qq.SALT_SZ + ct_len] if first else page_plain[:ct_len]
        ct = enc.encrypt(body, iv)
        h = hmac_mod.new(mac_key, ct + iv, getattr(hashlib, p.mac_algo))
        h.update(struct.pack("<I", pgno))
        head = salt if first else b""
        # SQLCipher 把 HMAC 写在页尾，填充在它前面
        return head + ct + iv + b"\x00" * pad_len + h.digest()

    pages = []
    for pgno in (1, 2):
        if pgno == 1:
            plain = qq.SQLITE_HDR + bytes((i * 7 + 1) % 256 for i in range(ct1)) + b"\x00" * p.reserve
        else:
            plain = bytes((i * 11 + 3) % 256 for i in range(ctn)) + b"\x00" * p.reserve
        pages.append((plain, seal(plain, pgno, pgno == 1)))

    try:
        with open(path, "wb") as f:
            f.write(b"SQLite header 3\x00".ljust(qq.HEADER_SZ, b"\x00"))
            for _plain, blob in pages:
                f.write(blob)

        db = qq.Database(path)
        ok, detail = db.structure_ok()
        _check(ok, f"结构判定失败：{detail}")
        _check("2 页" in detail, f"页数算错了：{detail}")

        page1 = db.page1()
        _check(qq.verify(passphrase, page1, p), "自己造的库都校验不过")
        _check(not qq.verify(b"wrong-passphrase", page1, p), "错口令居然通过了校验")

        got = qq.detect(passphrase, page1)
        _check(got is not None and got.name == p.name, f"参数自动探测不对：{got}")

        res = qq.decrypt_db(db, out, passphrase, p)
        _check(res.get("ok"), f"解密失败：{res.get('error')}")
        data = open(out, "rb").read()
        _check(len(data) == 2 * qq.PAGE_SZ, f"解密后大小不对：{len(data)}")
        _check(data[:16] == qq.SQLITE_HDR, "解密后 page1 不是 SQLite 头")
        _check(data[:qq.PAGE_SZ] == pages[0][0], "page1 内容与原文不一致")
        _check(data[qq.PAGE_SZ:] == pages[1][0], "page2 内容与原文不一致")
        return "QQ 库结构（1024 字节头 / 参数探测 / 逐页解密）"
    finally:
        shutil.rmtree(root, ignore_errors=True)


CHECKS = (check_aes, check_qq_roundtrip)


def run() -> bool:
    for name in ("stdout", "stderr"):
        try:
            getattr(sys, name).reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    print("=" * 66)
    print("  自检：不读微信/QQ 数据、不联网，只验证格式解析与解密逻辑")
    print(f"  环境：Python {platform.python_version()} / {platform.platform()}")
    print("=" * 66)
    ok = True
    for fn in CHECKS:
        try:
            print(f"  [OK]   {fn()}")
        except Exception as e:      # noqa: BLE001
            ok = False
            print(f"  [FAIL] {fn.__name__}: {type(e).__name__}: {e or repr(e)}")
            if not isinstance(e, Fail):
                traceback.print_exc()
    print("=" * 66)
    print("  全部通过 ✅" if ok else "  有失败项 ❌")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
