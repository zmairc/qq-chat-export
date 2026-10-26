# QQ NT 聊天记录导出（Windows）

把 QQ NT（新版 QQ 9.9.x，Electron 架构）存在本机的 `nt_msg.db` 解开，最终目标是像
[微信导出](https://github.com/zmairc/wechat-chat-export) 那样，导出成可搜索的网页 / 表格 / 纯文本。

**当前状态**：库结构、SQLCipher 参数探测、逐页解密已完成并通过自检；
**消息正文解析与导出还没做**，因为它依赖一次真实的解密样本（见下面「缺什么」）。

## 已确认的事实（本机实测，22 个库全部成立）

| 项目 | 结论 |
|---|---|
| 文件布局 | **1024 字节自定义头 + N × 4096 页**：`(文件大小 - 1024) % 4096 == 0` |
| 伪装的头部 | 头里写的是 `SQLite header 3`（真头是 `SQLite format 3\0`），故意让人认错 |
| 加密算法 | SQLCipher，AES-256-CBC |
| KDF 迭代 | **4000**（不是 SQLCipher 默认的 256000） |
| HMAC 算法 | 公开资料互相矛盾（SHA1 / SHA512 都有人说），所以代码里**不写死**，逐组试 |
| 密钥 | 16 位 ASCII passphrase |

## 快速开始

```bash
python qq_export.py probe                     # 找库 + 验证「1024 头 + 4096 页」（不需要密钥）
python qq_export.py decrypt --key <16位口令>   # 自动试参数、逐页解密到 work/qq_decrypted/
python qq_export.py schema                    # 打印解密后的表名与列名
```

密钥也可以放环境变量，避免留在命令历史里：

```powershell
$env:QQ_DB_KEY = "xxxxxxxxxxxxxxxx"
```

## 缺什么：口令不在内存里

QQ 的 passphrase 由 `nt_sqlite3_key_v2` 在打开数据库时传入，**只在函数调用那一瞬间存在**。
本项目实测扫过 7 个 QQ 进程共 900MB 内存、又按数据库路径邻近取候选，都没找到——
所以它确实不常驻。

社区工具（`QQBackup/qq-win-db-key`）的做法是：静态分析 `wrapper.node` 找到该函数，
用调试器拉起 QQ 并下断点，在用户重新登录时从寄存器里读出来。

那套做法需要调试介入 + 用户重新登录，与本项目「只读、不注入、不 hook」的原则冲突，
因此本项目**不自带取密钥功能**，只接受用户提供的口令（取一次可长期复用）。

## 参数自动探测

`qqexport/qq.py` 内置 6 组候选，逐个拿 page1 的 HMAC 去试，试通的才用来解密：

| 名称 | 迭代 | KDF | HMAC | 保留区 |
|---|---|---|---|---|
| `qq/sha1-48` | 4000 | SHA512 | SHA1 | 48 |
| `qq/sha1-36` | 4000 | SHA512 | SHA1 | 36 |
| `qq/sha512-80` | 4000 | SHA512 | SHA512 | 80 |
| `qq/legacy-sha1` | 4000 | SHA1 | SHA1 | 48 |
| `qq/iter64000` | 64000 | SHA512 | SHA1 | 48 |
| `sqlcipher-default` | 256000 | SHA512 | SHA512 | 80 |

页面布局（以保留区 48 为例）：

```
page1 : [salt 16][密文 4032][IV 16][填充 12][HMAC-SHA1 20]
其它页: [密文 4048][IV 16][填充 12][HMAC-SHA1 20]
```

注意 **HMAC 永远在页尾、填充在它前面**——和直觉相反，自检里专门造数据验证过。

## 自检

```bash
python -m qqexport.selftest            # 自己造两页加密库 → 校验 → 探测 → 解密回环
python -m unittest discover -s tests   # 同一批断言的 unittest 版本
```

自检**不读真实 QQ 数据、不联网、不需要第三方库**，读代码时也能验证它确实只在做解密。

## 计划

1. 拿到口令 → 跑通一次真实解密 → `schema` 打印真实列名
2. 解析消息体（QQ 是 protobuf：`MsgBody → repeated MsgContent`）
3. 媒体定位（`nt_data/` 下的图片与文件）
4. 复用微信那套渲染，输出 HTML / TXT / CSV

## 隐私与免责

- 全程本地运行，**不联网、不上传**；只处理你本人本机已登录账号的数据。
- 不注入、不 hook、不修改 QQ 任何文件。
- 请勿用于获取他人聊天记录或任何违法用途。
- 按 MIT 协议「按原样」提供，不保证长期可用（QQ 一升级格式就可能变）。
