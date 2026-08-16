# 国密算法验证实验仓库使用说明书

## 1. 项目简介

本仓库用于学习和验证中国商用密码算法。目前通过 Python 调用本机 OpenSSL，实现类似 CAVP/ACVP 的测试向量执行流程：

```text
JSON 测试向量
      ↓
统一入口 runner.py
      ↓
检查算法与参数
      ↓
调用 OpenSSL
      ↓
比较实际结果和预期结果
      ↓
输出 PASS/FAIL 和退出码
```

本项目没有从零实现密码算法，密码运算由 OpenSSL 完成。项目代码负责测试向量解析、参数校验、算法分派、OpenSSL 调用和结果判定。

当前项目是算法验证实验工具，不是完整的生产级文件加密软件，也不替代 GmSSL。

## 2. 当前功能

### 2.1 SM3

当前支持：

- 计算任意字节消息的 SM3 摘要
- 读取 JSON 格式 SM3 测试向量
- 验证消息 bit 长度
- 验证预期摘要长度和十六进制格式
- 调用 OpenSSL `dgst -sm3 -binary`
- 比较实际摘要与预期摘要
- 测试空消息、短消息和长消息

SM3 的输入是任意长度字节序列，输出固定为：

```text
256 bit = 32 byte = 64 个十六进制字符
```

SM3 是不可逆的杂凑算法，不是加密算法。

### 2.2 SM4

当前支持：

- SM4-ECB 加密和解密
- SM4-CBC 加密和解密
- SM4-CTR 加密和解密
- 128 bit 密钥检查
- CBC/CTR 的 128 bit IV 检查
- 明文、密文和密钥的十六进制检查
- 无 padding 的 ECB/CBC 整分组测试
- CTR 任意非空整字节长度测试
- ECB 国标单分组向量验证
- CBC 加解密往返和固定参数实验向量
- CTR 20 byte 加解密实验向量

SM4 的基本参数为：

```text
密钥长度：128 bit = 16 byte
分组长度：128 bit = 16 byte
```

当前执行器固定使用 `-nopad`。ECB/CBC 的明文和密文必须是 16 byte 的非空整数倍；CTR 不使用 padding，允许任意非空整字节长度。

### 2.3 SM4-CTR + HMAC-SM3

当前组合实验支持：

- 使用独立的 16 byte SM4 密钥和 32 byte HMAC 密钥
- 使用随机 16 byte IV 执行 SM4-CTR 加密
- 对版本、算法、IV、密文长度和密文计算 HMAC-SM3
- 使用恒定时间比较验证 tag，并且只在验证成功后解密
- 检测 IV、密文和 tag 篡改
- 通过 `gmcrypto.py` 生成双密钥文件并执行认证加密、认证解密
- 认证失败时不写出明文，默认拒绝覆盖已有输出

该接口是学习实验格式，不是经过标准化或安全审计的生产文件格式。

### 2.4 统一运行入口

`runner.py` 会读取 JSON 根对象中的 `algorithm` 字段：

```text
algorithm = SM3 -> 执行 SM3 逻辑
algorithm = HMAC-SM3 -> 执行 HMAC-SM3 逻辑
algorithm = SM4 -> 执行 SM4 逻辑
algorithm = SM4-CTR-HMAC-SM3 -> 执行加密认证组合逻辑
其他值         -> 报告不支持并返回退出码 2
```

目前保留 `sm4_runner.py`：

- 它包含 SM4 参数校验和 OpenSSL 调用逻辑。
- `runner.py` 将 SM4 请求分派给该模块。
- 它也可以作为兼容的独立 SM4 命令使用。

## 3. 项目结构

```text
gm-algorithm-validation/
├── README.md
├── gmcrypto.py                # 普通用户命令行工具
├── runner.py                  # SM3 实现和统一入口
├── hmac_sm3_runner.py         # HMAC-SM3 实现与向量校验
├── authenticated_sm4.py       # 认证 SM4 格式与编码规则
├── authenticated_sm4_runner.py # 认证 SM4 向量执行器
├── gmssl_backend.py            # 独立 GmSSL 交叉验证后端
├── sm4_runner.py              # SM4 实现与兼容入口
├── requirements-dev.txt       # 交叉验证开发依赖
├── vectors/
│   ├── sm3.json               # SM3 测试向量
│   ├── hmac-sm3.json          # HMAC-SM3 回归测试向量
│   ├── sm4-ctr-hmac-sm3.json  # 认证 SM4-CTR 实验向量
│   └── sm4.json               # SM4 ECB/CBC/CTR 测试向量
├── tests/
│   ├── test_sm3.py            # SM3 单元与集成测试
│   ├── test_hmac_sm3.py       # HMAC-SM3 向量执行器测试
│   ├── test_authenticated_sm4.py # 认证 SM4 格式与编码测试
│   ├── test_authenticated_sm4_runner.py # 认证 SM4 向量测试
│   ├── test_cross_validation.py # OpenSSL/GmSSL 交叉验证
│   ├── test_runner_backends.py # runner 后端选择测试
│   ├── test_sm4.py            # SM4 单元与集成测试
│   ├── test_gmcrypto.py        # 普通用户 SM3/HMAC-SM3 测试
│   └── test_runner_dispatch.py # 统一入口分派测试
├── examples/
│   └── message.txt            # SM3 文件摘要实验输入
├── docs/
│   ├── usage-guide.md         # 本说明书
│   ├── sm3-experiment.md      # SM3 实验记录
│   ├── hmac-sm3-experiment.md # HMAC-SM3 实验记录
│   ├── authenticated-sm4-experiment.md # 认证 SM4 阶段记录
│   ├── cross-validation.md    # 独立交叉验证记录
│   └── sm4-experiment.md      # SM4 实验记录
└── results/                   # 预留的结果输出目录
```

## 4. 环境要求

本项目当前在以下环境验证：

```text
Windows PowerShell
Python 3
OpenSSL 1.1.1i  8 Dec 2020
```

检查 Python：

```powershell
python --version
```

检查 OpenSSL：

```powershell
openssl version
```

检查 SM3：

```powershell
openssl list -digest-algorithms | Select-String SM3
```

检查 SM4：

```powershell
openssl list -cipher-algorithms | Select-String SM4
```

当前执行器要求 OpenSSL 至少提供：

```text
SM3
SM4-ECB
SM4-CBC
SM4-CTR
```

## 5. 基本使用方法

打开 PowerShell 并进入项目：

```powershell
cd C:\Users\16256\Documents\密码学\gm-algorithm-validation
```

查看帮助：

```powershell
python runner.py --help
```

统一命令格式：

```powershell
python runner.py <测试向量文件> [--backend openssl|gmssl|cross] [--openssl <openssl.exe路径>]
```

后端说明：

| 后端 | 行为 |
|---|---|
| `openssl` | 默认值，只使用 OpenSSL |
| `gmssl` | 只使用 Python gmssl，不查找 OpenSSL |
| `cross` | 同时运行两套后端并逐项比较 |

`gmssl` 和 `cross` 需要先安装 `requirements-dev.txt`。`--openssl` 只对 `openssl` 和 `cross` 有效。

普通用户计算 SM3 时使用：

```powershell
python gmcrypto.py sm3 --text "abc"
python gmcrypto.py sm3 --hex 616263
python gmcrypto.py sm3 --file examples\message.txt
```

三种输入必须且只能选择一种：

- `--text`：文本按指定编码转换成字节，默认 UTF-8。
- `--hex`：直接提供原始消息字节的十六进制表示。
- `--file`：由 OpenSSL 直接读取文件，适合大文件。

指定文本编码：

```powershell
python gmcrypto.py sm3 --text "示例" --encoding utf-8
```

指定 OpenSSL 路径：

```powershell
python gmcrypto.py sm3 --file examples\message.txt --openssl "C:\完整路径\openssl.exe"
```

生成 HMAC-SM3 tag：

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --text "abc"
```

验证已有 tag：

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --text "abc" --verify 0933617a88d312f6f9fb4b5f200e31a64d655e92f7fa2a43f55dfeeb8ab6788d
```

HMAC-SM3 同样支持 `--hex` 和 `--file`。生成模式输出 64 个十六进制字符；验证成功输出 `OK` 并返回 `0`，验证失败输出 `FAIL` 并返回 `1`。输入或环境错误返回 `2`。

生成认证加密密钥文件：

```powershell
python gmcrypto.py generate-auth-key --output auth-key.json
```

文件中分别保存 16 byte SM4 密钥和 32 byte HMAC 密钥。认证加密命令不接受命令行明文密钥：

```powershell
python gmcrypto.py encrypt-auth --key-file auth-key.json --text "国密实验" --output message.gmenc.json
python gmcrypto.py encrypt-auth --key-file auth-key.json --hex 616263 --output message.gmenc.json
python gmcrypto.py encrypt-auth --key-file auth-key.json --file examples\message.txt --output message.gmenc.json
```

验证认证 tag 并解密到文件：

```powershell
python gmcrypto.py decrypt-auth --key-file auth-key.json --package message.gmenc.json --output recovered.txt
```

加密结果是包含 `version`、`algorithm`、`iv`、`ciphertext` 和 `tag` 的 JSON 包。解密先完成 HMAC 验证，认证失败返回退出码 `1` 且不产生明文文件。输入、格式和环境错误返回 `2`。输出路径默认必须不存在，需要明确替换时使用 `--force`。

运行 SM4-CTR + HMAC-SM3 组合向量：

```powershell
python runner.py vectors\sm4-ctr-hmac-sm3.json
```

统一入口会校验双密钥、IV、明密文长度和 tag，并同时比较加密密文、认证 tag 和解密恢复明文。

运行 HMAC-SM3 JSON 回归向量：

```powershell
python runner.py vectors\hmac-sm3.json
```

该文件当前包含 1 个由 OpenSSL 1.1.1i 生成的回归向量，并已使用 Python gmssl 3.2.2 交叉验证；它不标记为官方标准向量。

## 6. 运行 SM3 验证

执行：

```powershell
python runner.py vectors\sm3.json
```

当前预期结果：

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

当前正式 JSON 文件包含 8 个用例，其中消息 `abc` 示例为：

```text
文本：abc
十六进制：616263
长度：24 bit
```

其 SM3 摘要为：

```text
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

向量由 2 个国标向量和 6 个边界回归向量组成。边界输入为空消息及 55、56、63、64、65 byte 全零消息；其摘要由 OpenSSL 1.1.1i 生成，并已使用 Python gmssl 3.2.2 交叉验证。

### 6.1 SM3 JSON 格式

```json
{
  "algorithm": "SM3",
  "source": "GB/T 32905-2016",
  "testGroups": [
    {
      "tests": [
        {
          "tcId": 1,
          "msg": "616263",
          "msgLen": 24,
          "md": "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        }
      ]
    }
  ]
}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `algorithm` | 必须为 `SM3` |
| `source` | 测试向量来源，执行器不参与计算 |
| `testGroups` | 测试组数组 |
| `tcId` | 唯一整数测试编号 |
| `msg` | 原始消息字节的十六进制表示 |
| `msgLen` | 消息 bit 长度，必须等于 `len(msg) × 4` |
| `md` | 预期的 256 bit SM3 摘要 |

注意：`msg` 的十六进制只是 JSON 中表示二进制数据的方法。OpenSSL 最终收到的是解码后的原始字节。

## 7. 运行 SM4 验证

执行：

```powershell
python runner.py vectors\sm4.json
```

当前预期结果：

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

也可以使用兼容入口：

```powershell
python sm4_runner.py vectors\sm4.json
```

推荐日常使用统一的 `runner.py`。

### 7.1 SM4 ECB JSON 格式

```json
{
  "mode": "ECB",
  "direction": "encrypt",
  "tests": [
    {
      "tcId": 1,
      "key": "0123456789abcdeffedcba9876543210",
      "pt": "0123456789abcdeffedcba9876543210",
      "ct": "681edf34d206965e86b3e94f536e4246"
    }
  ]
}
```

### 7.2 SM4 CBC JSON 格式

```json
{
  "mode": "CBC",
  "direction": "encrypt",
  "tests": [
    {
      "tcId": 3,
      "key": "0123456789abcdeffedcba9876543210",
      "iv": "000102030405060708090a0b0c0d0e0f",
      "pt": "0123456789abcdeffedcba9876543210",
      "ct": "a9a268883a336315bac0c9c9ff350ab1"
    }
  ]
}
```

### 7.3 SM4 CTR JSON 格式

CTR 可以处理非 16 byte 整数倍的数据。以下用例的明文和密文均为 20 byte：

```json
{
  "mode": "CTR",
  "direction": "encrypt",
  "tests": [
    {
      "tcId": 9,
      "key": "0123456789abcdeffedcba9876543210",
      "iv": "000102030405060708090a0b0c0d0e0f",
      "pt": "0123456789abcdeffedcba987654321001020304",
      "ct": "07bbd906b40da542d4514d1a97fccb7a6e050e4f"
    }
  ]
}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `algorithm` | JSON 根对象中必须为 `SM4` |
| `mode` | 当前支持 `ECB`、`CBC` 或 `CTR` |
| `direction` | `encrypt` 或 `decrypt` |
| `tcId` | 全文件唯一整数测试编号 |
| `key` | 16 byte 密钥，共 32 个十六进制字符 |
| `iv` | CBC/CTR 必需的 16 byte IV/初始计数器；ECB 禁止携带 |
| `pt` | 明文十六进制；ECB/CBC 按 16 byte 对齐，CTR 可为任意非空整字节长度 |
| `ct` | 密文十六进制，长度必须与明文相同 |

加密测试以 `pt` 为输入、`ct` 为预期输出。解密测试以 `ct` 为输入、`pt` 为预期输出。

当前 10 个 SM4 用例包括 2 个 ECB 国标单分组向量、2 个 ECB 两分组推导向量、4 个 CBC 实验向量，以及 2 个 CTR 20 byte 实验向量。CBC/CTR 实验向量由 OpenSSL 1.1.1i 生成，并已使用 Python gmssl 3.2.2 交叉验证；它们不作为官方标准向量。

## 8. 指定 OpenSSL 路径

默认情况下，程序从系统 `PATH` 查找 `openssl`。

如果找不到，可以使用：

```powershell
python runner.py vectors\sm3.json --openssl "C:\完整路径\openssl.exe"
python runner.py vectors\hmac-sm3.json --openssl "C:\完整路径\openssl.exe"
python runner.py vectors\sm4-ctr-hmac-sm3.json --openssl "C:\完整路径\openssl.exe"
python runner.py vectors\sm4.json --openssl "C:\完整路径\openssl.exe"
```

程序不会自动安装 OpenSSL。

## 9. 程序输出和退出码

### 9.1 全部通过

```text
[PASS] tcId=1
...
Total: N, Passed: N, Failed: 0
```

退出码：

```text
0
```

### 9.2 计算结果不一致

```text
[FAIL] tcId=1
       expected: ...
       actual:   ...
```

退出码：

```text
1
```

### 9.3 输入或环境错误

例如算法名称错误、JSON 损坏、密钥长度错误或找不到 OpenSSL：

```text
Error: ...
```

退出码：

```text
2
```

在 PowerShell 中查看上一条命令的退出码：

```powershell
$LASTEXITCODE
```

## 10. 运行测试

运行全部测试：

```powershell
python -m unittest discover -s tests -v
```

当前共有 101 项测试：

- 9 项 SM3 测试
- 19 项 SM4 测试
- 7 项 `gmcrypto.py` 普通用户 SM3 CLI 测试
- 8 项 HMAC-SM3 CLI 测试
- 6 项普通用户认证加密 CLI 测试
- 8 项 HMAC-SM3 向量执行器测试
- 5 项统一入口分派测试
- 21 项认证 SM4 格式、加解密与篡改测试
- 6 项认证 SM4 向量执行器测试
- 7 项 OpenSSL/GmSSL 交叉验证测试
- 5 项 runner 后端选择测试

当前预期结果：

```text
Ran 101 tests in ...

OK
```

只运行 SM3 测试：

```powershell
python -m unittest tests.test_sm3 -v
```

只运行 SM4 测试：

```powershell
python -m unittest tests.test_sm4 -v
```

只运行统一入口测试：

```powershell
python -m unittest tests.test_runner_dispatch -v
```

## 11. 主要代码说明

### 11.1 `runner.py`

主要职责：

- 解析统一命令行参数
- 读取 JSON 根对象
- 根据 `algorithm` 分派算法
- 实现 SM3 输入校验与 OpenSSL 调用
- 统一处理错误和退出码

主要函数：

| 函数 | 作用 |
|---|---|
| `parse_args()` | 解析向量文件和 OpenSSL 路径 |
| `load_document()` | 读取通用 JSON 根对象 |
| `extract_tests()` | 提取并校验 SM3 测试用例 |
| `sm3_digest()` | 调用 OpenSSL 计算 SM3 |
| `run_tests()` | 执行 SM3 测试并汇总结果 |
| `run_document()` | 根据算法名称分派 SM3、HMAC-SM3、SM4 或认证 SM4 |
| `main()` | 统一程序入口和错误处理 |

### 11.2 `gmcrypto.py`

主要职责：

- 为普通用户提供文本、十六进制和文件三种 SM3 输入方式
- 生成和验证 HMAC-SM3 tag
- 生成认证加密双密钥文件
- 使用密钥文件完成 SM4-CTR + HMAC-SM3 认证加密与解密
- 认证成功后才原子写出明文，并默认拒绝覆盖已有文件
- 明确处理文本编码和十六进制错误
- SM3 文件摘要由 OpenSSL 文件接口读取；HMAC 文件输入读取为字节后复用统一底层函数
- 只输出摘要，便于脚本继续处理

主要函数：

| 函数 | 作用 |
|---|---|
| `decode_hex_message()` | 将十六进制输入转换为原始字节 |
| `encode_text()` | 按指定编码转换文本 |
| `sm3_file_digest()` | 计算文件 SM3 摘要 |
| `run_sm3()` | 选择文本、十六进制或文件输入 |
| `hmac_sm3_runner.hmac_sm3()` | 调用 OpenSSL 生成 HMAC-SM3 tag |
| `run_hmac_sm3()` | 生成 tag 或使用恒定时间比较进行验证 |
| `load_auth_keys()` | 读取并校验 JSON 双密钥文件 |
| `run_generate_auth_key()` | 使用安全随机源生成双密钥文件 |
| `run_encrypt_auth()` | 加密并输出认证 JSON 包 |
| `run_decrypt_auth()` | 认证成功后解密并写出明文 |
| `write_atomic()` | 使用同目录临时文件写入并提供覆盖保护 |
| `main()` | 普通用户命令入口和错误处理 |

### 11.3 `sm4_runner.py`

主要职责：

- 校验 SM4 ECB/CBC/CTR 测试组
- 检查密钥、IV、明文和密文
- 生成 OpenSSL `enc` 参数
- 执行 SM4 加密或解密
- 比较结果并输出汇总

主要函数：

| 函数 | 作用 |
|---|---|
| `extract_tests()` | 提取并校验 SM4 测试用例 |
| `require_hex()` | 检查十六进制和长度要求 |
| `sm4_crypt()` | 调用 OpenSSL 执行 SM4 |
| `run_tests()` | 执行 SM4 测试并汇总结果 |
| `main()` | 独立兼容入口 |

## 12. 如何添加测试向量

### 12.1 添加 SM3 向量

1. 在 `vectors/sm3.json` 的 `tests` 数组中增加对象。
2. 使用尚未重复的 `tcId`。
3. 把原始消息转换成十六进制写入 `msg`。
4. 填写正确的 bit 长度。
5. 从正式标准或独立可信实现取得 `md`。
6. 运行统一入口和全部单元测试。

### 12.2 添加 SM4 向量

1. 选择 `ECB`、`CBC` 或 `CTR` 测试组。
2. 选择 `encrypt` 或 `decrypt` 方向。
3. 使用尚未重复的 `tcId`。
4. 填写正好 16 byte 的密钥。
5. CBC/CTR 填写正好 16 byte 的 IV；CTR 中该值是初始计数器。
6. 确保明文和密文长度相同。ECB/CBC 必须是非空 16 byte 整数倍；CTR 可为任意非空整字节长度。
7. 标注向量来源，不把本地生成结果冒充正式标准向量。
8. 运行统一入口和全部单元测试。

修改 JSON 后可以先检查语法：

```powershell
python -m json.tool vectors\sm3.json
python -m json.tool vectors\sm4.json
```

## 13. 常见错误

### 13.1 找不到 OpenSSL

```text
Error: OpenSSL was not found
```

处理方法：检查：

```powershell
Get-Command openssl
```

或使用 `--openssl` 指定完整路径。

### 13.2 SM4 密钥长度错误

SM4 密钥必须是：

```text
16 byte = 32 个十六进制字符
```

### 13.3 CBC/CTR 缺少 IV

CBC 和 CTR 测试必须提供 16 byte 的 `iv`。ECB 不使用 IV，也不应出现 `iv` 字段。

### 13.4 明文不是整分组

当前关闭 padding。ECB/CBC 明文和密文必须是：

```text
16、32、48、64 ... byte
```

CTR 不需要 padding，可以处理任意非空整字节长度，例如 1、15、20 byte。

### 13.5 文本与十六进制混淆

字符串：

```text
abc
```

对应的 ASCII/UTF-8 字节十六进制为：

```text
616263
```

把文本字符 `616263` 直接作为消息，与把十六进制解码为字节 `abc` 不同。

## 14. 安全限制

- SM3 是摘要算法，不能加密或恢复原文。
- 普通 SM3 摘要不能证明发送者身份；消息认证可研究 HMAC-SM3。
- SM4-ECB 会暴露重复分组结构，不适合实际文件加密。
- SM4-CBC 不提供完整性认证，不能单独抵抗主动篡改。
- SM4-CTR 可处理任意长度，但不提供完整性认证；同一密钥下绝不能重复 IV/初始计数器。
- 当前固定 IV 仅用于可重复实验，不代表生产系统应固定 IV。
- 普通 `SM4-CTR` 不提供完整性；`gmcrypto.py` 的实验格式额外使用 HMAC-SM3 认证，并为每次加密随机生成 IV。
- 测试向量通过只证明所测试输入输出一致，不代表整个实现经过安全认证。
- 不要在仓库、JSON、命令历史或测试代码中保存真实生产密钥。
- `--key-hex` 会出现在 shell 历史和进程参数中，只适合本地学习实验。
- `encrypt-auth` 和 `decrypt-auth` 只接受 `--key-file`。密钥文件包含明文密钥，应放在仓库外、限制访问且不得提交到 Git。
- 认证加密输入文件和 JSON 包上限为 64 MiB，当前会完整读入内存。
- 认证 JSON 格式未经标准化、安全审计或生产互操作验证。

## 15. 推荐日常流程

每次修改后依次运行：

```powershell
python runner.py vectors\sm3.json
python runner.py vectors\hmac-sm3.json
python runner.py vectors\sm4-ctr-hmac-sm3.json
python runner.py vectors\sm4.json
python -m unittest discover -s tests -v
git diff --check
git status
```

全部通过后再提交：

```powershell
git add <本次修改的文件>
git diff --cached --stat
git commit -m "描述本次修改"
```

## 16. 后续扩展方向

尚未实现但可以继续开展：

1. 提取 SM3、SM4 公共的 JSON、OpenSSL 和错误处理模块。
2. 使用 OpenSSL EVP API 编写 C 语言后端。
3. 使用同一批向量交叉验证 Python 和 C 后端。
4. 为后端不一致报告增加更细的用例编号和结构化结果输出。
5. 为 HMAC-SM3 增加独立标准向量，并逐步将其 CLI 也迁移到密钥文件。
6. 研究流式大文件处理、操作系统密钥库和标准化认证加密容器。
7. 增加 SM2 密钥生成、签名、验签和加解密实验。
8. 逐步适配更接近 ACVP 的 JSON 能力描述与结果格式。
