# OpenSSL 与 GmSSL 独立交叉验证记录

## 验证目的

项目原有实验向量主要通过 OpenSSL 执行。为了避免只使用同一实现生成并验证实验结果，本阶段增加 Python `gmssl` 3.2.2 作为第二套密码原语实现，对现有全部向量进行交叉验证。

交叉验证一致只能说明两套实现对当前输入输出一致，不等同于 ACVTS 认证、安全审计或生产认证。

## 验证环境

验证日期：2026-08-16

```text
Windows PowerShell
Python 3.9.1
OpenSSL 1.1.1i  8 Dec 2020
gmssl 3.2.2
```

开发依赖记录在 `requirements-dev.txt`：

```text
gmssl==3.2.2
```

安装与运行：

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest tests.test_cross_validation -v
```

## 后端结构

`gmssl_backend.py` 只导入 `gmssl.sm3` 和 `gmssl.sm4`，不导入项目中的 OpenSSL runner，也不启动 `openssl` 子进程。

后端提供：

- `gmssl_sm3()`：调用 GmSSL SM3 原语。
- `gmssl_hmac_sm3()`：按照 HMAC 结构组合 GmSSL SM3 原语。
- `gmssl_sm4_block()`：调用 GmSSL SM4 原始单分组接口。
- `gmssl_sm4_crypt()`：在单分组原语之上组合无 padding ECB、CBC 和 CTR。

GmSSL 3.2.2 自带的 `crypt_ecb()` 和 `crypt_cbc()` 会处理 padding，不能直接匹配项目的 `-nopad` 向量。因此本项目使用 `set_key()` 和 `one_round()`，自行组合工作模式。CTR 计数器按照 128 bit 无符号大端整数递增。

## 验证范围与结果

| 算法 | JSON 向量数 | OpenSSL | GmSSL 3.2.2 | 结果 |
|---|---:|---|---|---|
| SM3 | 8 | 通过 | 通过 | 一致 |
| HMAC-SM3 | 1 | 通过 | 通过 | 一致 |
| SM4 ECB/CBC/CTR | 10 | 通过 | 通过 | 一致 |
| SM4-CTR-HMAC-SM3 | 1 | 通过 | 通过 | 一致 |
| 合计 | 20 | 通过 | 通过 | 一致 |

另外验证了：

- SM4 国标单分组加密与解密。
- 空消息认证组合在两套后端中产生相同密文和 tag。
- GmSSL 后端源码未导入 `subprocess` 或项目中的 OpenSSL runner。

专项测试结果：

```text
Ran 7 tests in ...

OK
```

全项目测试结果：

```text
Ran 95 tests in ...

OK
```

## 当前边界

- 交叉验证测试需要安装 `requirements-dev.txt` 中的开发依赖。
- `runner.py` 已支持 `--backend openssl|gmssl|cross`；OpenSSL 仍是默认后端。
- `gmssl` 模式不查找 OpenSSL；`cross` 模式逐项比较两套结果，不一致时返回退出码 `1`。
- HMAC 模式层以及 ECB/CBC/CTR 组合代码属于本项目包装逻辑，密码原语来自 GmSSL。
- 14 个非标准实验/回归向量的 `source` 已更新为 OpenSSL 1.1.1i 生成、Python gmssl 3.2.2 交叉验证。标准和推导向量的来源说明保持不变。
- Python `gmssl` 项目与 GmSSL 官方 C 项目不能简单视为同一个发行物，文档中明确记录的是 PyPI `gmssl 3.2.2`。
