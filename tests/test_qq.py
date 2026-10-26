"""QQ 模块的基本断言（不依赖真实数据）。"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qqexport import qq


class TestStructure(unittest.TestCase):
    def test_reject_too_small(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "small.db")
            open(p, "wb").write(b"SQLite header 3\x00" + b"\x00" * 500)
            ok, detail = qq.Database(p).structure_ok()
            self.assertFalse(ok)
            self.assertIn("太小", detail)

    def test_reject_bad_padding(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "odd.db")
            open(p, "wb").write(b"\x00" * (qq.HEADER_SZ + qq.PAGE_SZ + 7))
            ok, detail = qq.Database(p).structure_ok()
            self.assertFalse(ok)
            self.assertIn("整数倍", detail)

    def test_accept_aligned(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ok.db")
            open(p, "wb").write(b"\x00" * (qq.HEADER_SZ + 3 * qq.PAGE_SZ))
            ok, detail = qq.Database(p).structure_ok()
            self.assertTrue(ok)
            self.assertIn("3 页", detail)


class TestKeys(unittest.TestCase):
    def test_derive_is_deterministic(self):
        salt = bytes(range(16))
        a = qq.derive(b"0123456789abcdef", salt, qq.PARAM_SETS[0])
        b = qq.derive(b"0123456789abcdef", salt, qq.PARAM_SETS[0])
        self.assertEqual(a, b)
        self.assertEqual(len(a[0]), 32)

    def test_wrong_key_rejected(self):
        page1 = bytes(16) + b"\x00" * (qq.PAGE_SZ - 16)
        self.assertFalse(qq.verify(b"0123456789abcdef", page1, qq.PARAM_SETS[0]))
        self.assertIsNone(qq.detect(b"0123456789abcdef", page1))

    def test_param_sets_sane(self):
        # 保留区至少要放得下 IV(16) 与 HMAC；36 = 16+20 是 HMAC-SHA1 的紧排写法，
        # 48 是 SQLCipher 3 的默认（留了 12 字节空档），两种都留作候选
        for p in qq.PARAM_SETS:
            self.assertGreaterEqual(p.reserve, 16 + p.mac_len, f"{p.name} 保留区太小")
            self.assertLess(p.reserve, qq.PAGE_SZ // 2, f"{p.name} 保留区大得离谱")
            self.assertGreater(p.kdf_iter, 0)


if __name__ == "__main__":
    unittest.main()
