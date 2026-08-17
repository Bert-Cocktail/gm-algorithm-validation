# SM2 签名与加密实验记录

## 实验目标

本阶段建立 SM2 签名验证执行器，验证 JSON 输入校验、SM2 用户标识参与摘要、DER/RAW 签名转换，以及 OpenSSL 和 Python GmSSL 两个后端的一致性。

当前已完成向量签名验证、PEM 密钥生成、文件签名和验签、公钥加密、私钥解密、三种密文格式转换，以及本地 ACVP 风格的签名验证与解密请求。

## 算法与数据约定

- 曲线：`sm2p256v1`
- 公钥格式：65 byte 未压缩椭圆曲线点，即 `04 || X || Y`
- 向量签名格式：ASN.1 DER `SEQUENCE(INTEGER r, INTEGER s)`
- GmSSL 接口签名格式：64 byte `r || s`
- 消息和用户标识：十六进制编码的原始字节
- 用户标识不能为空，长度上限由 SM2 的 16 bit `ENTL` 字段决定
- 当前 OpenSSL 命令行后端要求用户标识能够解释为 UTF-8 文本

SM2 签名验证使用的摘要不是单独的 `SM3(message)`。执行器按照下式处理用户标识、公钥和消息：

```text
ENTL = 用户标识的位长度，以 16 bit 大端整数编码
ZA   = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
e    = SM3(ZA || message)
```

GmSSL 后端计算 `ZA` 和 `e` 后调用 SM2 原始验签接口。OpenSSL 后端通过 `dgst -sm3` 和 `distid` 选项执行同一语义的验证。

## 文件

```text
sm2_runner.py       独立 SM2 向量执行器
sm2_cipher.py       SM2 加解密、DER 解析和密文格式转换
sm2_encryption_runner.py  SM2 加密实验向量执行器
vectors/sm2.json    SM2 签名验证回归向量
vectors/sm2-encryption.json  SM2 加密与格式向量
tests/test_sm2.py   输入、编码、后端和执行行为测试
tests/test_sm2_encryption.py  加解密、完整性和格式测试
```

## 测试向量

`vectors/sm2.json` 当前包含 6 个用例：

1. 正确消息和签名；
2. 空消息的正确签名；
3. 签名后修改消息；
4. 修改签名的 `s`；
5. 使用另一把有效公钥；
6. 使用另一用户标识。

正向签名由 Python `gmssl 3.2.2` 使用测试专用私钥和固定随机数生成，以保证文件可复现。固定随机数只能用于测试，实际 SM2 签名不得复用或固定随机数。仓库向量不包含实际业务私钥。

## 输入校验

执行器会拒绝：

- 错误的算法、曲线、操作或签名格式；
- 重复或非整数 `tcId`；
- 非十六进制、奇数长度或 `msgLen` 不一致的消息；
- 长度错误、压缩格式、坐标越界或不在 SM2 曲线上的公钥；
- 空、过长或 OpenSSL 无法处理的用户标识；
- 非 DER、截断、非规范编码或 `r`、`s` 越界的签名；
- 非布尔类型的 `expected`。

## 运行方法

仅使用 Python GmSSL：

```powershell
python sm2_runner.py vectors/sm2.json --backend gmssl
```

使用 OpenSSL：

```powershell
python sm2_runner.py vectors/sm2.json --backend openssl
```

交叉验证：

```powershell
python sm2_runner.py vectors/sm2.json --backend cross
```

指定另一 OpenSSL 可执行文件：

```powershell
python sm2_runner.py vectors/sm2.json --backend cross --openssl "C:\path\to\openssl.exe"
```

统一入口和普通用户命令：

```powershell
python runner.py vectors\sm2.json --backend cross --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
python gmcrypto.py sm2-keygen --private-key sm2-private.pem --public-key sm2-public.pem --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
python gmcrypto.py sm2-sign --private-key sm2-private.pem --input examples\message.txt --signature message.sig --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
python gmcrypto.py sm2-verify --public-key sm2-public.pem --input examples\message.txt --signature message.sig --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
```

## 公钥加密、私钥解密与格式转换

SM2 加密输入为接收者的 `sm2p256v1` 公钥和非空短消息，输出由临时椭圆曲线点 `C1`、密文 `C2` 和 SM3 完整性值 `C3` 组成。OpenSSL 3 使用 ASN.1 DER，字段顺序为 `x, y, C3, C2`。Python `gmssl 3.2.2` 使用不带 `04` 点前缀的原始 C1C3C2；本项目对外统一要求 C1 是 `04 || X || Y`，支持：

- `der`：OpenSSL 兼容 DER；
- `c1c3c2`：65 byte C1，随后 C3 和 C2；
- `c1c2c3`：65 byte C1，随后 C2 和 C3。

```powershell
python gmcrypto.py sm2-encrypt --public-key sm2-public.pem --input examples\message.txt --output message.c1c3c2 --format c1c3c2 --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
python gmcrypto.py sm2-convert --input message.c1c3c2 --output message.der --from-format c1c3c2 --to-format der
python gmcrypto.py sm2-decrypt --private-key sm2-private.pem --input message.der --output recovered.txt --format der --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
```

GmSSL Python 包的原始 `decrypt()` 不主动验证 C3。本项目会重新计算 `SM3(x2 || M || y2)` 并进行恒定时间比较，C3 不匹配时拒绝输出明文。

`vectors/sm2-encryption.json` 当前有 5 个用例：可复现的 `sm2p256v1` 解密回归向量、C3 篡改拒绝、两个后端的随机加密回环，以及两个公开附录密文的格式转换用例。

公开密文来自 IETF `draft-shen-sm2-ecdsa-02` Appendix C.2。该附录使用自己的 Fp-256 示例曲线，不是当前默认的 `sm2p256v1`，因此这里只验证字段拆分和格式转换，不宣称它是当前后端的标准曲线加解密向量。固定 `d=1`、`k=2` 的用例属于本地回归向量，也不冒充官方认证向量。

```powershell
python runner.py vectors\sm2-encryption.json --backend cross --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
python -m unittest tests.test_sm2_encryption -v
```

运行专项测试：

```powershell
python -m unittest tests.test_sm2 -v
```

## 退出码

- `0`：全部向量结果符合预期；
- `1`：至少一个验证结果错误，或交叉后端结果不一致；
- `2`：输入、依赖或运行环境错误。

## 环境差异

本机 PATH 中的 OpenSSL 1.1.1i 能列出 SM2 曲线，但其构建无法通过 `dgst` 执行 SM2 签名验证，会报告 `invalid digest type`。这说明“能够列出 SM2”并不等于该构建的命令行签名接口可用。

实验同时使用系统中 Git 附带的 OpenSSL 3.5.4 进行交叉验证。运行者应使用支持 SM2 签名的 OpenSSL 版本，并可通过 `--openssl` 指定其路径。

## 当前结论与限制

当前实现能够解析并验证 SM2 DER 签名，使用 PEM 密钥执行签名、验签、加密和解密，并在 DER、C1C3C2、C1C2C3 之间严格转换。它是本地学习和回归验证工具，不代表 ACVTS 接入或算法认证。

下一阶段可研究可复核的随机加密请求、更多与现行 `sm2p256v1` 精确匹配的公开向量，以及 SM2 密钥交换实验。
