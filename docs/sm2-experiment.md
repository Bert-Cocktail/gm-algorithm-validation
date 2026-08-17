# SM2 签名与加密实验记录

## 1. 实验目标

本实验不从零实现椭圆曲线运算，而是调用 OpenSSL 和 Python GmSSL，建立可重复运行的 SM2 验证流程：

```text
JSON 向量或 PEM 文件 -> 参数与编码校验 -> SM2 后端 -> 结果判定 -> PASS/FAIL
```

实验目标包括：验证 `sm2p256v1` 签名与验签、用户 ID 绑定、PEM 密钥操作、公钥加密与私钥解密、三种密文格式、C3 完整性、双后端交叉验证，以及本地 ACVP 风格请求。

## 2. SM2 基本原理

SM2 是基于椭圆曲线的公钥密码算法。本仓库使用国家标准曲线 `sm2p256v1`。私钥 `d` 是 `[1, n-1]` 内的整数，公钥为曲线点：

```text
P = dG
```

JSON 公钥统一编码为 65 byte 未压缩点：

```text
04 || X(32 byte) || Y(32 byte)
```

| 算法 | 类型 | 典型用途 |
|---|---|---|
| SM2 | 非对称公钥算法 | 签名、短消息加密、密钥协商 |
| SM3 | 摘要算法 | 计算固定长度摘要 |
| SM4 | 对称分组密码 | 高效加密数据 |

## 3. SM2 签名与用户 ID

SM2 签名不是简单地对 `SM3(message)` 签名。用户 ID、曲线参数和公钥会形成预摘要 `ZA`：

```text
ENTL = ID 的 bit 长度，以 16 bit 大端整数编码
ZA   = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
e    = SM3(ZA || message)
```

签名使用私钥和每次都应重新生成的随机数 `k`，输出 `(r, s)`。向量使用 ASN.1 DER `SEQUENCE(INTEGER r, INTEGER s)`；Python GmSSL 原始接口使用 64 byte `r || s`，所以执行器会严格转换两种编码。

消息、公钥或用户 ID 任一变化都应使验签失败。固定或复用签名随机数可能泄露私钥；仓库中的固定随机数只用于生成可复现向量。

## 4. SM2 加密、解密与完整性

加密方使用接收者公钥和新的随机数 `k` 计算临时点、共享点及 SM3 KDF。密文包含：

```text
C1：临时椭圆曲线点 kG
C2：消息与 KDF 输出异或后的密文
C3：SM3(x2 || message || y2) 完整性值
```

同一公钥和明文重复加密时，随机数不同，因此密文通常不同。正确验证方式是：

```text
decrypt(privateKey, encrypt(publicKey, message)) == message
```

解密必须验证 C3。本项目会重新计算 C3 并恒定时间比较；校验失败时拒绝输出明文。SM2 适合短消息，大文件通常应采用“SM2 保护随机对称密钥，SM4 加密文件”的混合加密结构。

## 5. 密钥、签名和密文编码

| 数据 | 编码 |
|---|---|
| 普通用户私钥 | PEM PKCS#8 `PRIVATE KEY` |
| 普通用户公钥 | PEM `PUBLIC KEY` |
| JSON 公钥 | `04 || X || Y` 十六进制 |
| 签名 | ASN.1 DER |
| `der` 密文 | `SEQUENCE(x, y, C3, C2)` |
| `c1c3c2` | `04 || X || Y || C3 || C2` |
| `c1c2c3` | `04 || X || Y || C2 || C3` |

格式转换只改变字段编码和排列，不重新加密。解析器拒绝非规范 DER、越界坐标、错误点前缀、空 C2、非 32 byte C3 和离曲线点。

## 6. 实验环境与后端

```text
操作环境：Windows PowerShell / GitHub Actions Ubuntu
执行器：Python 3
后端一：OpenSSL 命令行
后端二：Python gmssl 3.2.2
```

`openssl` 适合验证 OpenSSL 互操作；`gmssl` 是第二套实现；`cross` 同时运行两者。随机签名或加密结果不能直接逐字节比较，应比较验签结果或解密原文。

部分 OpenSSL 1.1.1 构建能列出 SM2 曲线，却不能执行 SM2 签名或加解密。版本号不能替代实际能力检查，可通过 `--openssl` 指定支持相应操作的 OpenSSL 3。

## 7. 实验文件

| 文件 | 作用 |
|---|---|
| `sm2_runner.py` | 签名向量、DER/RAW 转换和验签 |
| `sm2_cipher.py` | 加解密、C3 校验和密文转换 |
| `sm2_encryption_runner.py` | 加密、解密和格式向量执行器 |
| `gmcrypto.py` | 普通用户密钥、签名和加解密命令 |
| `vectors/sm2.json` | 6 个签名正、负向量 |
| `vectors/sm2-encryption.json` | 5 个解密、篡改、回环和转换向量 |
| `acvp/requests/sm2-request.json` | 本地 ACVP 风格请求样例 |
| `tests/test_sm2.py` | 签名、编码、输入和后端测试 |
| `tests/test_sm2_encryption.py` | 密文、完整性、私钥编码和回环测试 |

## 8. 签名向量实验

| tcId | 场景 | 预期 |
|---:|---|---|
| 1 | 正确消息、公钥、ID 和签名 | 通过 |
| 2 | 空消息的有效签名 | 通过 |
| 3 | 签名后修改消息 | 拒绝 |
| 4 | 修改签名的 `s` | 拒绝 |
| 5 | 替换为另一把有效公钥 | 拒绝 |
| 6 | 替换用户 ID | 拒绝 |

```powershell
python runner.py vectors\sm2.json --backend gmssl
python runner.py vectors\sm2.json --backend cross --openssl "C:\path\to\openssl.exe"
```

这些用例验证签名同时绑定消息、用户 ID 和公钥。正向数据属于本地回归向量，不冒充 ACVTS 或认证向量。

## 9. 加密与格式向量实验

| tcId | 场景 | 目的 |
|---:|---|---|
| 1 | 固定测试私钥解密 C1C3C2 | 验证已知回归密文 |
| 2 | 修改 C3 | 验证篡改拒绝 |
| 3 | 随机加密后立即解密 | 验证回环和随机路径 |
| 4 | C1C2C3 转 C1C3C2 | 验证字段重排 |
| 5 | C1C2C3 转 DER | 验证 ASN.1 编码 |

```powershell
python runner.py vectors\sm2-encryption.json --backend gmssl
python runner.py vectors\sm2-encryption.json --backend cross --openssl "C:\path\to\openssl.exe"
```

`tcId=1` 使用公开测试专用 `d=1` 和固定 `k=2`。`tcId=4/5` 来自 IETF `draft-shen-sm2-ecdsa-02` Appendix C.2，但该附录使用自己的示例曲线，因此这里只验证格式，不声称能在当前曲线上解密。

## 10. 普通用户操作流程

生成密钥、签名并验签：

```powershell
python gmcrypto.py sm2-keygen --private-key sm2-private.pem --public-key sm2-public.pem --openssl "C:\path\to\openssl.exe"
python gmcrypto.py sm2-sign --private-key sm2-private.pem --input examples\message.txt --signature message.sig --user-id 1234567812345678 --openssl "C:\path\to\openssl.exe"
python gmcrypto.py sm2-verify --public-key sm2-public.pem --input examples\message.txt --signature message.sig --user-id 1234567812345678 --openssl "C:\path\to\openssl.exe"
```

加密、转换和解密：

```powershell
python gmcrypto.py sm2-encrypt --public-key sm2-public.pem --input examples\message.txt --output message.c1c3c2 --format c1c3c2 --openssl "C:\path\to\openssl.exe"
python gmcrypto.py sm2-convert --input message.c1c3c2 --output message.der --from-format c1c3c2 --to-format der
python gmcrypto.py sm2-decrypt --private-key sm2-private.pem --input message.der --output recovered.txt --format der --openssl "C:\path\to\openssl.exe"
```

输出默认不得已存在，需要替换时使用 `--force`。私钥应保存在仓库外并限制操作系统访问权限。

## 11. ACVP 风格随机加密请求

SM2 请求组支持 `verify`、`encrypt` 和 `decrypt`。随机加密测试提供测试专用公私钥、`msg`、`msgLen` 和 `ciphertextFormat`，响应返回 `testPassed` 和 `ct`。

这里携带私钥只为本地回环验证；正常加密方只应获得接收者公钥。`--verify-responses` 解密保存的随机密文并比较原文，不要求重新运行后生成相同密文。这仍是本地格式实验，不是正式 ACVTS 请求。

## 12. 输入校验与失败实验

执行器会拒绝：

- 错误算法、曲线、操作、签名或密文格式；
- 重复或非整数 `tcId`；
- 非十六进制、奇数长度或 `msgLen` 不一致的数据；
- 长度错误、坐标越界、压缩或离曲线公钥；
- 零值、越界或长度错误的私钥；
- 空或超过 `ENTL` 范围的用户 ID；
- 截断、非规范或整数越界的 DER 签名和密文；
- 空 C2、错误长度 C3、错误 C1 和 C3 不匹配；
- 非布尔 `expected` 和重复测试编号。

无效签名或预期的篡改拒绝属于测试结果；格式错误、缺少依赖或 OpenSSL 不可用属于输入/环境错误。

## 13. 测试结果

```powershell
python -m unittest tests.test_sm2 tests.test_sm2_encryption -v
python -m unittest discover -s tests -v
```

当前完整测试为 192 项通过，另有 1 项在本机旧 OpenSSL 不支持 SM2 签名时按条件跳过。GitHub Actions 同时执行回归向量、ACVP 风格请求复核和报告归档。

## 14. 退出码

- `0`：向量符合预期或普通用户操作成功；
- `1`：验签失败、结果不一致或交叉后端不一致；
- `2`：输入、依赖、文件或运行环境错误。

## 15. 安全性分析

- 私钥必须保密，公钥需要与正确身份可靠绑定。
- 签名随机数不得固定或复用，用户 ID 必须按协议一致管理。
- SM2 加密具有随机性，不能依赖固定密文判断正确性。
- C3 验证通过前不得把解密结果交给调用者。
- 格式转换不增加安全性，也不会修复被篡改的密文。
- SM2 适合短消息和密钥材料，不适合直接加密大文件。
- 测试专用 `d=1`、固定 `k` 和样例密钥绝不能用于业务。
- 测试通过不等于实现经过安全审计或密码产品认证。

## 16. 实验结论与后续工作

本实验形成了 SM2 签名、验签、随机加密、解密、完整性检查和格式互操作的完整学习闭环，并能使用两套后端和结构化请求复核。

后续可扩充现行曲线公开向量、密钥生成请求、SM2 密钥交换、OpenSSL EVP C 后端，以及经过审查的混合加密和密钥管理方案。
