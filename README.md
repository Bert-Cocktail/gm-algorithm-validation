# GM Algorithm Validation Lab

这是一个面向国密算法学习的实验仓库。项目调用 OpenSSL 完成密码运算，并按照“读取测试向量、校验输入、执行算法、比较预期结果、输出 PASS/FAIL”的流程验证 SM3 和 SM4。

项目不从零实现密码算法，也不以替代 GmSSL 为目标。当前重点是建立可复现、可测试、可继续扩展的国密算法实验框架。

## 当前功能

### SM3

- 使用 OpenSSL 计算 SM3 摘要
- 读取简化 ACVP 风格的 JSON 测试向量
- 校验 `algorithm`、`tcId`、`msg`、`msgLen` 和 `md`
- 比较实际摘要和预期摘要

### SM4

- 使用 OpenSSL 执行 SM4-ECB 和 SM4-CBC
- 支持加密与解密测试向量
- 校验 128 bit 密钥和 CBC 的 128 bit IV
- 校验明文、密文的十六进制格式和分组长度
- 使用无 padding 模式验证整分组输入
- 拒绝重复 `tcId`、不支持的模式和错误参数

两个执行器都会输出每个测试用例的 PASS/FAIL，并区分测试失败与输入、环境错误。

当前尚未实现：GmSSL 后端、C API、padding、认证加密、SM2、性能测试和 ACVTS 接入。

## 项目结构

```text
gm-algorithm-validation/
├── README.md
├── gmcrypto.py
├── runner.py
├── sm4_runner.py
├── vectors/
│   ├── sm3.json
│   └── sm4.json
├── tests/
│   ├── test_sm3.py
│   └── test_sm4.py
├── examples/
│   └── message.txt
├── docs/
│   ├── sm3-experiment.md
│   └── sm4-experiment.md
└── results/
```

完整的功能、命令、JSON 字段、代码结构和常见错误说明参见 [使用说明书](docs/usage-guide.md)。

`examples/message.txt` 只用于 SM3 文件摘要实验。当前 SM4 实验直接使用 JSON 中的十六进制明文，不需要修改该文件。

## 环境要求

- Windows PowerShell
- Python 3
- 支持 SM3、SM4-ECB 和 SM4-CBC 的 OpenSSL

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

统一入口会根据 JSON 中的 `algorithm` 字段自动选择 SM3 或 SM4。运行 SM4 向量：

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

Total: 8, Passed: 8, Failed: 0
```

如果 OpenSSL 没有加入 `PATH`，可以显式指定程序路径：

```powershell
python runner.py vectors\sm3.json --openssl "C:\path\to\openssl.exe"
python runner.py vectors\sm4.json --openssl "C:\path\to\openssl.exe"
```

## 退出码

两个执行器使用相同约定：

- `0`：所有测试向量通过
- `1`：至少一个实际结果与预期结果不一致
- `2`：测试向量、参数或 OpenSSL 环境有误

## 运行单元测试

运行全部测试：

```powershell
python -m unittest discover -s tests -v
```

当前共有 33 项测试：

- 9 项 SM3 测试
- 14 项 SM4 测试
- 3 项统一入口分派测试
- 7 项普通用户 CLI 测试

本次实测结果：

```text
Ran 33 tests in ...

OK
```

SM3 测试包括标准消息、空消息、长消息、十六进制格式、长度校验、错误摘要和 OpenSSL 缺失处理。

SM4 测试包括 ECB 国标向量加密与解密、CBC 加解密往返、密钥与分组长度校验、IV 规则、错误密文、不支持模式和 OpenSSL 缺失处理。

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

当前 `sm3.json` 共 8 个用例：2 个国标向量，以及空消息和 55、56、63、64、65 byte 全零消息组成的 6 个边界回归向量。回归向量由 OpenSSL 1.1.1i 生成，已标注等待独立实现交叉验证。

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
- `iv`：CBC 使用的 128 bit 初始向量；ECB 不使用 IV
- `pt`：明文的十六进制表示
- `ct`：密文的十六进制表示
- `mode`：当前支持 `ECB`、`CBC`
- `direction`：`encrypt` 或 `decrypt`

当前 `sm4.json` 共 8 个用例：

- `tcId=1`、`tcId=2`：`GB/T 32907-2016` 单分组标准向量。
- `tcId=3`、`tcId=4`：本地 OpenSSL 单分组 CBC 实验向量。
- `tcId=5`、`tcId=6`：根据标准结果和 ECB 分组独立性得到的两分组推导向量。
- `tcId=7`、`tcId=8`：本地 OpenSSL 两分组 CBC 实验向量，等待独立实现交叉验证。

两个相同明文分组在 ECB 中产生相同密文分组，在 CBC 中产生不同密文分组。

详细内容参见 [SM4 实验记录](docs/sm4-experiment.md)。

## 当前限制与安全说明

- 当前 SM4 执行器固定使用 `-nopad`，明文和密文必须是 16 byte 的非空整数倍。
- ECB 仅用于标准与推导向量验证，不适合实际文件或重复结构数据加密。
- CBC 中 IV 不需要保密，但必须正确传递，并应按协议要求生成和避免重复。
- CBC 本身不提供完整性认证，实际系统需要采用经过审查的认证加密方案或加密加认证结构。
- 测试向量通过只能说明所测输入输出一致，不能单独证明整个密码库不存在安全漏洞。
- `gmcrypto.py` 当前只向普通用户开放 SM3；SM4 在补齐安全文件格式、padding 和完整性认证前仍只用于测试向量实验。

## 下一步计划

1. 使用 OpenSSL EVP API 编写 C 语言 SM3、SM4 程序。
2. 让同一批 JSON 向量验证命令行后端和 C 后端。
3. 为真实文件设计带 padding、IV 保存和完整性认证的安全方案。
4. 增加 GmSSL 后端，并继续开展 SM2 实验。
