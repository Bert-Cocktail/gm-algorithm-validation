# SM4 分组密码实验记录

## 1. 实验目标

本实验不从零实现 SM4，而是调用 OpenSSL 的 SM4 实现，建立可重复运行的算法验证流程：

```text
JSON 测试向量 -> 参数校验 -> OpenSSL SM4 -> 比较预期结果 -> PASS/FAIL
```

实验目标包括：

1. 使用国标单分组向量验证 SM4-ECB 加密与解密。
2. 使用固定密钥和 IV 完成 SM4-CBC、SM4-CTR 加解密实验。
3. 观察 CBC 模式中 IV 对密文的影响。
4. 验证执行器能够拒绝错误密钥、分组长度、IV 和模式。
5. 保证新增 SM4 功能不会破坏已有 SM3 功能。

## 2. SM4 基本原理

SM4 是对称分组密码算法。它使用同一个密钥完成加密和解密：

```text
128 bit 明文分组 + 128 bit 密钥 -> SM4 加密 -> 128 bit 密文分组
128 bit 密文分组 + 128 bit 密钥 -> SM4 解密 -> 128 bit 明文分组
```

SM4 的分组长度和密钥长度均为 128 bit，即 16 byte。算法包含 32 轮迭代，解密使用与加密相同的轮变换结构，但轮密钥顺序相反。

SM4 本身定义的是单个分组变换。ECB、CBC、CTR 等工作模式规定了如何处理消息。

## 3. 实验环境

```text
操作环境：Windows PowerShell
执行器：Python 3
密码后端：OpenSSL 1.1.1i  8 Dec 2020
```

本机 OpenSSL 已确认支持：

```text
SM4-ECB
SM4-CBC
SM4-CFB
SM4-CTR
SM4-OFB
```

当前实验执行器开放 SM4-ECB、SM4-CBC 和 SM4-CTR。本机 OpenSSL 未列出 SM4-GCM，因此本阶段不实现 SM4-GCM。

## 4. 实验文件

| 文件 | 作用 |
|---|---|
| `sm4_runner.py` | 读取、校验并执行 SM4 测试向量 |
| `vectors/sm4.json` | 保存 ECB 标准/推导向量和 CBC/CTR 实验向量 |
| `tests/test_sm4.py` | 验证 OpenSSL 输出、CBC/CTR 往返和错误输入处理 |
| `docs/sm4-experiment.md` | 记录实验过程和结论 |

`examples/message.txt` 属于 SM3 文件摘要实验。当前 SM4 直接使用 JSON 中的十六进制明文，因此不需要更新该文件。

## 5. 测试向量执行流程

运行命令：

```powershell
python runner.py vectors\sm4.json
```

执行器依次完成：

1. 以 UTF-8 读取 JSON。
2. 确认算法名称为 `SM4`。
3. 检查模式是否为 `ECB`、`CBC` 或 `CTR`。
4. 检查方向是否为 `encrypt` 或 `decrypt`。
5. 检查 `tcId` 是否为唯一整数。
6. 检查密钥是否正好为 16 byte。
7. CBC/CTR 检查 IV 是否正好为 16 byte；ECB 禁止携带 IV。
8. ECB/CBC 要求数据为非空 16 byte 整数倍；CTR 允许任意非空整字节长度。
8. 检查明文和密文是否为合法十六进制，并按 16 byte 分组对齐。
9. 通过标准输入将原始字节传递给 OpenSSL。
10. 使用 `-nopad` 禁用 OpenSSL 默认 padding。
11. 比较实际输出与预期结果并报告 PASS/FAIL。

## 6. ECB 标准向量实验

采用 `GB/T 32907-2016` 的单分组向量：

```text
Key:        0123456789abcdeffedcba9876543210
Plaintext:  0123456789abcdeffedcba9876543210
Ciphertext: 681edf34d206965e86b3e94f536e4246
```

验证内容：

- `tcId=1`：使用密钥加密明文，结果应为标准密文。
- `tcId=2`：使用同一密钥解密标准密文，结果应恢复原文。
- `tcId=5`：加密两个相同明文分组，得到两个相同密文分组。
- `tcId=6`：解密两个相同密文分组，恢复两个相同明文分组。

ECB 直接、独立地加密每个分组。相同密钥下，相同明文分组会产生相同密文分组，因此会暴露重复结构。这里使用 ECB 是为了验证 SM4 单分组算法，不是推荐实际系统采用 ECB。

## 7. CBC 加解密实验

CBC 加密在每个明文分组进入 SM4 前，将其与前一个密文分组异或。第一个分组没有前序密文，因此使用 IV：

```text
C0 = IV
Ci = SM4-Encrypt(Key, Pi XOR C(i-1))
```

本实验参数：

```text
Key:       0123456789abcdeffedcba9876543210
IV:        000102030405060708090a0b0c0d0e0f
Plaintext: 0123456789abcdeffedcba9876543210
Ciphertext:a9a268883a336315bac0c9c9ff350ab1
```

`tcId=3`、`tcId=4` 验证单分组 CBC 加密和解密。`tcId=7`、`tcId=8` 验证两个相同明文分组的 CBC 加密和解密。CBC 密文由 OpenSSL 1.1.1i 得到，并已使用 Python gmssl 3.2.2 交叉验证；它们仍用于实验和回归，不能表述为独立国标测试向量。

## 8. CTR 加解密实验

CTR 将连续计数器值用 SM4 加密，产生密钥流，再与消息异或。加密和解密使用相同的密钥流操作，因此可以处理不是 16 byte 整数倍的消息。

`tcId=9`、`tcId=10` 使用 20 byte 消息验证 CTR 加密和解密。密文由 OpenSSL 1.1.1i 生成，并已使用 Python gmssl 3.2.2 交叉验证；它们仍是实验向量，不是本项目声称的国标向量。

新增 `tcId=11` 至 `tcId=14` 验证 ECB/CBC 三分组加解密；`tcId=15` 至 `tcId=28` 验证 CTR 的 1、15、16、17、31、32、33 byte 加解密边界。它们同样由 OpenSSL 生成并经 Python gmssl 3.2.2 交叉验证。

CTR 的 IV 在这里作为初始计数器。它不必保密，但在同一密钥下绝不能重复；重复会导致密钥流复用并泄露明文关系。

实际执行结果：

```text
[PASS] tcId=1 mode=ECB direction=encrypt
[PASS] tcId=5 mode=ECB direction=encrypt
[PASS] tcId=2 mode=ECB direction=decrypt
[PASS] tcId=6 mode=ECB direction=decrypt
[PASS] tcId=3 mode=CBC direction=encrypt
[PASS] tcId=7 mode=CBC direction=encrypt
[PASS] tcId=4 mode=CBC direction=decrypt
[PASS] tcId=8 mode=CBC direction=decrypt
[PASS] tcId=9 mode=CTR direction=encrypt
[PASS] tcId=10 mode=CTR direction=decrypt

Total: 28, Passed: 28, Failed: 0
```

## 9. IV 对比实验

保持密钥和明文不变，只改变 IV：

```text
IV1 = 000102030405060708090a0b0c0d0e0f
CT1 = a9a268883a336315bac0c9c9ff350ab1

IV2 = 000102030405060708090a0b0c0d0e00
CT2 = 150060375930151f12e6f363b0617fc6
```

两个密文不同，说明 IV 会影响 CBC 的第一个密文分组，并通过链式结构影响后续分组。

从实验可以得到：

- 相同 key、IV 和明文会产生相同密文。
- 保持 key 和明文不变，改变 IV 会改变密文。
- 解密必须使用与加密对应的 IV。
- IV 不需要保密，但必须正确传递，并应根据具体协议满足不可预测或不重复等要求。

## 10. 无 padding 的影响

`sm4_runner.py` 固定向 OpenSSL 传递：

```text
-nopad
```

因此 ECB/CBC 的明文和密文必须是 16 byte 的非空整数倍。CTR 通过密钥流异或处理数据，不需要 padding，允许任意非空整字节长度。该设计适合验证标准分组向量，因为它不会把 PKCS#7 padding 混入算法输出。

普通文件和任意长度文本通常不是 16 byte 的整数倍。若以后用 ECB/CBC 实现文件加密，需要明确 padding 方案；使用 CTR 虽不需要 padding，仍须安全保存模式、IV/初始计数器和认证信息。不能直接把当前测试执行器当作通用文件加密工具。

## 11. 单元测试结果

SM4 共完成 19 项测试：

| 测试 | 目的 | 结果 |
|---|---|---|
| ECB 标准向量加密 | 验证标准密文 | 通过 |
| ECB 标准向量解密 | 验证恢复明文 | 通过 |
| CBC 两分组往返 | 验证加密后可正确解密 | 通过 |
| CTR 20 byte 加解密 | 验证非整分组消息和预期密文 | 通过 |
| CTR 缺少或错误长度 IV | 拒绝无效参数 | 通过 |
| CTR 空消息 | 拒绝空输入 | 通过 |
| 大写十六进制 | 验证输入规范化 | 通过 |
| 密钥过短 | 拒绝不足 16 byte 的密钥 | 通过 |
| 密钥过长 | 拒绝超过 16 byte 的密钥 | 通过 |
| 非十六进制密钥 | 拒绝非法编码 | 通过 |
| 非整分组明文 | 拒绝无 padding 下的错误长度 | 通过 |
| 重复 `tcId` | 拒绝歧义编号 | 通过 |
| GCM 模式 | 拒绝当前不支持的模式 | 通过 |
| CBC 缺少 IV | 拒绝缺失参数 | 通过 |
| ECB 携带 IV | 拒绝无意义参数 | 通过 |
| 错误预期密文 | 确认 FAIL 和退出码 | 通过 |
| OpenSSL 缺失 | 确认环境错误提示 | 通过 |

统一入口根据 JSON 的 `algorithm` 字段自动选择 SM3、HMAC-SM3、SM4 或 SM4-CTR-HMAC-SM3。运行全部单元测试：

```powershell
python -m unittest discover -s tests -v
```

本次实测结果：

```text
Ran 136 tests in ...

OK
```

其中 SM4 单元测试为 19 项；普通用户 CLI 包含 7 项 SM3 测试和 13 项 HMAC-SM3 测试。正式 SM4 JSON 已扩充到 28 个向量，新增 ECB/CBC 三分组实验及 CTR 的 1、15、16、17、31、32、33 byte 加解密边界。

## 12. 安全性分析

- SM4 提供可逆的机密性变换，与不可逆的 SM3 摘要不同。
- ECB 会泄露重复分组结构，只适合本实验中的单分组验证。
- CBC 隐藏重复明文分组需要正确使用 IV，但 CBC 本身不提供完整性认证。
- CTR 可处理任意长度消息，但同一密钥下重复初始计数器会造成严重信息泄露。
- CTR 与 CBC 一样不提供完整性认证，攻击者可以篡改密文并影响解密结果。
- 攻击者可能篡改 CBC 密文并可预测地影响解密结果，因此实际系统不能只加密而不认证。
- 当前 CBC 实验使用固定 IV 是为了结果可复现，不代表生产系统应固定使用该 IV。
- 测试向量通过只能证明当前输入输出一致，不能证明密码库整体不存在漏洞。

## 13. 实验结论

本实验完成了基于 OpenSSL 的 SM4-ECB、SM4-CBC 和 SM4-CTR 验证闭环。当前 28 个正式 JSON 向量全部通过 OpenSSL/GmSSL 交叉验证，19 项 SM4 单元测试均通过。

实验验证了 SM4 的 128 bit 密钥、ECB/CBC 分组约束、CBC 加解密往返、CTR 非整分组处理以及 IV/计数器规则。当前成果是算法测试向量执行器，还不是面向实际文件的完整加密方案。

## 14. 后续工作

1. 使用 OpenSSL EVP API 编写 C 语言 SM4 程序。
2. 使用相同 JSON 向量交叉验证 Python 执行器和 C 后端。
3. 研究 padding、IV 序列化和加密文件格式。
4. 增加完整性认证，避免仅使用裸 CBC 或裸 CTR。
5. 使用现有多后端 runner 继续开展 SM2 实验。
