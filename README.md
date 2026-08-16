# GM Algorithm Validation Lab

这是一个面向国密算法学习的实验仓库。项目调用 OpenSSL 完成密码运算，支持 SM3、HMAC-SM3 和 SM4 实验，并按照“读取测试向量、校验输入、执行算法、比较预期结果、输出 PASS/FAIL”的流程进行验证。

项目不从零实现密码算法，也不以替代 GmSSL 为目标。当前重点是建立可复现、可测试、可继续扩展的国密算法实验框架。

## 当前功能

### SM3

- 使用 OpenSSL 计算 SM3 摘要
- 读取简化 ACVP 风格的 JSON 测试向量
- 校验 `algorithm`、`tcId`、`msg`、`msgLen` 和 `md`
- 比较实际摘要和预期摘要

### SM4

- 使用 OpenSSL 执行 SM4-ECB、SM4-CBC 和 SM4-CTR
- 支持加密与解密测试向量
- 校验 128 bit 密钥以及 CBC/CTR 的 128 bit IV
- 校验明文、密文的十六进制格式和分组长度
- 使用无 padding 模式验证 ECB/CBC 整分组输入和 CTR 任意非空字节输入
- 拒绝重复 `tcId`、不支持的模式和错误参数

### HMAC-SM3

- 使用十六进制密钥对文本、十六进制消息或文件生成认证 tag
- 使用恒定时间比较验证已有 tag
- 正确验证输出 `OK`，不匹配输出 `FAIL`
- tag 固定为 32 byte，即 64 个十六进制字符

### SM4-CTR + HMAC-SM3 实验基础

- 固定双密钥规则：16 byte SM4 密钥和 32 byte HMAC 密钥
- 定义包含版本、算法、IV、密文和 tag 的 JSON 数据包
- 定义稳定、无歧义的 HMAC 二进制输入编码
- 使用 Encrypt-then-MAC 完成加密认证
- 验证 tag 成功后才执行解密
- 支持空消息、任意整字节消息、随机 IV 和篡改检测

### GmSSL 独立交叉验证

- 使用 Python `gmssl 3.2.2` 作为第二套密码原语实现
- 交叉验证全部 20 个 SM3、HMAC-SM3、SM4 和认证组合向量
- 使用 GmSSL 原始 SM4 分组接口组合无 padding ECB、CBC 和 CTR
- `runner.py` 支持 `openssl`、`gmssl` 和 `cross` 三种后端
- `cross` 会逐项比较 OpenSSL 与 GmSSL，任何不一致都返回测试失败

两个执行器都会输出每个测试用例的 PASS/FAIL，并区分测试失败与输入、环境错误。

当前尚未实现：C API、padding、生产级认证文件格式、SM2、性能测试和 ACVTS 接入。

## 项目结构

```text
gm-algorithm-validation/
├── README.md
├── gmcrypto.py
├── runner.py
├── hmac_sm3_runner.py
├── authenticated_sm4.py
├── authenticated_sm4_runner.py
├── gmssl_backend.py
├── sm4_runner.py
├── requirements-dev.txt
├── vectors/
│   ├── sm3.json
│   ├── hmac-sm3.json
│   ├── sm4-ctr-hmac-sm3.json
│   └── sm4.json
├── tests/
│   ├── test_sm3.py
│   ├── test_hmac_sm3.py
│   ├── test_authenticated_sm4.py
│   ├── test_authenticated_sm4_runner.py
│   ├── test_cross_validation.py
│   ├── test_runner_backends.py
│   ├── test_sm4.py
│   ├── test_gmcrypto.py
│   └── test_runner_dispatch.py
├── examples/
│   └── message.txt
├── docs/
│   ├── sm3-experiment.md
│   ├── hmac-sm3-experiment.md
│   ├── authenticated-sm4-experiment.md
│   ├── cross-validation.md
│   └── sm4-experiment.md
└── results/
```

完整的功能、命令、JSON 字段、代码结构和常见错误说明参见 [使用说明书](docs/usage-guide.md)。

`examples/message.txt` 只用于 SM3 文件摘要实验。当前 SM4 实验直接使用 JSON 中的十六进制明文，不需要修改该文件。

## 环境要求

- Windows PowerShell
- Python 3
- 支持 SM3、SM4-ECB、SM4-CBC 和 SM4-CTR 的 OpenSSL

本次实验实际使用：

```text
OpenSSL 1.1.1i  8 Dec 2020
```

检查环境：

```powershell
python --version
openssl version
openssl list -digest-algorithms | Select-String SM3
openssl list -cipher-algorithms | Select-String SM4
```

## 快速开始

进入仓库：

```powershell
cd C:\Users\16256\Documents\密码学\gm-algorithm-validation
```

普通用户可以直接计算 SM3：

```powershell
python gmcrypto.py sm3 --text "abc"
python gmcrypto.py sm3 --hex 616263
python gmcrypto.py sm3 --file examples\message.txt
```

三种方式都输出 64 个十六进制字符的 SM3 摘要。`--text` 默认使用 UTF-8，可通过 `--encoding` 指定其他文本编码；`--file` 由 OpenSSL 直接读取，Python 不会把整个文件载入内存。

生成 HMAC-SM3 tag：

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --text "abc"
```

验证 tag：

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --text "abc" --verify 0933617a88d312f6f9fb4b5f200e31a64d655e92f7fa2a43f55dfeeb8ab6788d
```

HMAC 验证成功返回 `OK` 和退出码 `0`，不匹配返回 `FAIL` 和退出码 `1`。

运行 SM4-CTR + HMAC-SM3 组合向量：

```powershell
python runner.py vectors\sm4-ctr-hmac-sm3.json
```

当前结果：

```text
[PASS] tcId=1 algorithm=SM4-CTR-HMAC-SM3

Total: 1, Passed: 1, Failed: 0
```

运行 HMAC-SM3 JSON 回归向量：

```powershell
python runner.py vectors\hmac-sm3.json
```

运行 SM3 标准与边界回归向量：

```powershell
python runner.py vectors\sm3.json
```

当前结果：

```text
[PASS] tcId=1
[PASS] tcId=2
[PASS] tcId=3
[PASS] tcId=4
[PASS] tcId=5
[PASS] tcId=6
[PASS] tcId=7
[PASS] tcId=8

Total: 8, Passed: 8, Failed: 0
```

统一入口会根据 JSON 中的 `algorithm` 字段自动选择 SM3、HMAC-SM3、SM4 或 SM4-CTR-HMAC-SM3。运行 SM4 向量：

```powershell
python runner.py vectors\sm4.json
```

当前结果：

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

Total: 10, Passed: 10, Failed: 0
```

选择密码后端：

```powershell
python runner.py vectors\sm3.json --backend openssl
python runner.py vectors\sm3.json --backend gmssl
python runner.py vectors\sm3.json --backend cross
```

- `openssl`：默认后端，只运行 OpenSSL。
- `gmssl`：只运行 Python gmssl，不要求 OpenSSL 在 `PATH`。
- `cross`：两套后端都运行，并要求每次密码运算结果一致。

如果 OpenSSL 没有加入 `PATH`，可以在 `openssl` 或 `cross` 后端显式指定程序路径：

```powershell
python runner.py vectors\sm3.json --openssl "C:\path\to\openssl.exe"
python runner.py vectors\hmac-sm3.json --openssl "C:\path\to\openssl.exe"
python runner.py vectors\sm4-ctr-hmac-sm3.json --openssl "C:\path\to\openssl.exe"
python runner.py vectors\sm4.json --openssl "C:\path\to\openssl.exe"
```

## 退出码

两个执行器使用相同约定：

- `0`：所有测试向量通过
- `1`：至少一个实际结果与预期结果不一致
- `2`：测试向量、参数或所选后端环境有误

## 运行单元测试

运行全部测试：

```powershell
python -m unittest discover -s tests -v
```

当前共有 95 项测试：

- 9 项 SM3 测试
- 19 项 SM4 测试
- 7 项普通用户 SM3 CLI 测试
- 8 项 HMAC-SM3 CLI 测试
- 8 项 HMAC-SM3 向量执行器测试
- 5 项统一入口分派测试
- 21 项认证 SM4 格式、加解密与篡改测试
- 6 项认证 SM4 向量执行器测试
- 7 项 OpenSSL/GmSSL 交叉验证测试
- 5 项 runner 后端选择测试

本次实测结果：

```text
Ran 95 tests in ...

OK
```

SM3 测试包括标准消息、空消息、长消息、十六进制格式、长度校验、错误摘要和 OpenSSL 缺失处理。

SM4 测试包括 ECB 国标向量加解密、CBC 与 CTR 往返、CTR 非整分组输入、密钥与 IV 校验、错误密文、不支持模式和 OpenSSL 缺失处理。

## SM3 测试向量

`vectors/sm3.json` 使用十六进制表示原始消息：

```json
{
  "tcId": 1,
  "msg": "616263",
  "msgLen": 24,
  "md": "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
}
```

- `msg`：原始消息的十六进制表示
- `msgLen`：消息的 bit 长度
- `md`：预期的 256 bit SM3 摘要

当前 `sm3.json` 共 8 个用例：2 个国标向量，以及空消息和 55、56、63、64、65 byte 全零消息组成的 6 个边界回归向量。回归向量由 OpenSSL 1.1.1i 生成，并已使用 Python gmssl 3.2.2 交叉验证。

详细内容参见 [SM3 实验记录](docs/sm3-experiment.md)。

## SM4 测试向量

SM4 测试用例示例：

```json
{
  "tcId": 3,
  "key": "0123456789abcdeffedcba9876543210",
  "iv": "000102030405060708090a0b0c0d0e0f",
  "pt": "0123456789abcdeffedcba9876543210",
  "ct": "a9a268883a336315bac0c9c9ff350ab1"
}
```

- `key`：128 bit SM4 密钥
- `iv`：CBC/CTR 使用的 128 bit 初始值；ECB 不使用 IV
- `pt`：明文的十六进制表示
- `ct`：密文的十六进制表示
- `mode`：当前支持 `ECB`、`CBC`、`CTR`
- `direction`：`encrypt` 或 `decrypt`

当前 `sm4.json` 共 10 个用例：

- `tcId=1`、`tcId=2`：`GB/T 32907-2016` 单分组标准向量。
- `tcId=3`、`tcId=4`：OpenSSL 单分组 CBC 实验向量，已使用 Python gmssl 3.2.2 交叉验证。
- `tcId=5`、`tcId=6`：根据标准结果和 ECB 分组独立性得到的两分组推导向量。
- `tcId=7`、`tcId=8`：OpenSSL 两分组 CBC 实验向量，已使用 Python gmssl 3.2.2 交叉验证。
- `tcId=9`、`tcId=10`：OpenSSL 20 byte CTR 加解密实验向量，已使用 Python gmssl 3.2.2 交叉验证。

两个相同明文分组在 ECB 中产生相同密文分组，在 CBC 中产生不同密文分组。CTR 可处理非 16 byte 整数倍的数据。

详细内容参见 [SM4 实验记录](docs/sm4-experiment.md)。

## 当前限制与安全说明

- 当前 SM4 执行器固定使用 `-nopad`。ECB/CBC 明文和密文必须是 16 byte 的非空整数倍；CTR 允许任意非空整字节长度。
- ECB 仅用于标准与推导向量验证，不适合实际文件或重复结构数据加密。
- CBC 中 IV 不需要保密，但必须正确传递，并应按协议要求生成和避免重复。
- CTR 的 IV/初始计数器在同一密钥下绝不能重复，否则会泄露明文之间的关系。
- CBC 本身不提供完整性认证，实际系统需要采用经过审查的认证加密方案或加密加认证结构。
- CTR 本身同样不提供完整性认证，不能把可处理任意长度误认为可直接安全用于文件。
- 测试向量通过只能说明所测输入输出一致，不能单独证明整个密码库不存在安全漏洞。
- `gmcrypto.py` 当前只向普通用户开放 SM3；SM4 在补齐安全文件格式、padding 和完整性认证前仍只用于测试向量实验。
- `--key-hex` 会出现在命令历史和进程参数中，只适合学习实验，不应直接传入真实生产密钥。

## 下一步计划

1. 使用 OpenSSL EVP API 编写 C 语言 SM3、SM4 程序。
2. 让同一批 JSON 向量验证命令行后端和 C 后端。
3. 为真实文件设计带 padding、IV 保存和完整性认证的安全方案。
4. 继续开展 SM2 实验，并使用 OpenSSL/GmSSL 交叉验证。
