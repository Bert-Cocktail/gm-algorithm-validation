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
- 128 bit 密钥检查
- CBC 的 128 bit IV 检查
- 明文、密文和密钥的十六进制检查
- 无 padding 的整分组测试
- ECB 国标单分组向量验证
- CBC 加解密往返和固定参数实验向量

SM4 的基本参数为：

```text
密钥长度：128 bit = 16 byte
分组长度：128 bit = 16 byte
```

当前执行器固定使用 `-nopad`，因此明文和密文必须是 16 byte 的非空整数倍。

### 2.3 统一运行入口

`runner.py` 会读取 JSON 根对象中的 `algorithm` 字段：

```text
algorithm = SM3 -> 执行 SM3 逻辑
algorithm = SM4 -> 执行 SM4 逻辑
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
├── sm4_runner.py              # SM4 实现与兼容入口
├── vectors/
│   ├── sm3.json               # SM3 测试向量
│   └── sm4.json               # SM4 ECB/CBC 测试向量
├── tests/
│   ├── test_sm3.py            # SM3 单元与集成测试
│   ├── test_sm4.py            # SM4 单元与集成测试
│   └── test_runner_dispatch.py # 统一入口分派测试
├── examples/
│   └── message.txt            # SM3 文件摘要实验输入
├── docs/
│   ├── usage-guide.md         # 本说明书
│   ├── sm3-experiment.md      # SM3 实验记录
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
python runner.py <测试向量文件> [--openssl <openssl.exe路径>]
```

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

向量由 2 个国标向量和 6 个边界回归向量组成。边界输入为空消息及 55、56、63、64、65 byte 全零消息；其摘要由 OpenSSL 1.1.1i 生成，等待独立实现交叉验证。

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

Total: 8, Passed: 8, Failed: 0
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

字段说明：

| 字段 | 含义 |
|---|---|
| `algorithm` | JSON 根对象中必须为 `SM4` |
| `mode` | 当前支持 `ECB` 或 `CBC` |
| `direction` | `encrypt` 或 `decrypt` |
| `tcId` | 全文件唯一整数测试编号 |
| `key` | 16 byte 密钥，共 32 个十六进制字符 |
| `iv` | CBC 必需的 16 byte IV；ECB 禁止携带 |
| `pt` | 明文十六进制，长度必须按 16 byte 对齐 |
| `ct` | 密文十六进制，长度必须与明文相同 |

加密测试以 `pt` 为输入、`ct` 为预期输出。解密测试以 `ct` 为输入、`pt` 为预期输出。

当前 8 个 SM4 用例包括 2 个 ECB 国标单分组向量、2 个 ECB 两分组推导向量，以及 4 个 CBC 单分组/两分组实验向量。两个相同明文分组在 ECB 中产生相同密文分组，在 CBC 中产生不同密文分组。

## 8. 指定 OpenSSL 路径

默认情况下，程序从系统 `PATH` 查找 `openssl`。

如果找不到，可以使用：

```powershell
python runner.py vectors\sm3.json --openssl "C:\完整路径\openssl.exe"
python runner.py vectors\sm4.json --openssl "C:\完整路径\openssl.exe"
```

程序不会自动安装 OpenSSL。

## 9. 程序输出和退出码

### 9.1 全部通过

```text
[PASS] tcId=1
...
Total: 8, Passed: 8, Failed: 0
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

当前共有 33 项测试：

- 9 项 SM3 测试
- 14 项 SM4 测试
- 3 项统一入口分派测试
- 7 项 `gmcrypto.py` 普通用户 CLI 测试

当前预期结果：

```text
Ran 33 tests in ...

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
| `run_document()` | 根据算法名称分派 SM3 或 SM4 |
| `main()` | 统一程序入口和错误处理 |

### 11.2 `gmcrypto.py`

主要职责：

- 为普通用户提供文本、十六进制和文件三种 SM3 输入方式
- 明确处理文本编码和十六进制错误
- 对文件调用 OpenSSL 文件接口，避免 Python 整体读取
- 只输出摘要，便于脚本继续处理

主要函数：

| 函数 | 作用 |
|---|---|
| `decode_hex_message()` | 将十六进制输入转换为原始字节 |
| `encode_text()` | 按指定编码转换文本 |
| `sm3_file_digest()` | 计算文件 SM3 摘要 |
| `run_sm3()` | 选择文本、十六进制或文件输入 |
| `main()` | 普通用户命令入口和错误处理 |

### 11.3 `sm4_runner.py`

主要职责：

- 校验 SM4 ECB/CBC 测试组
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

1. 选择 `ECB` 或 `CBC` 测试组。
2. 选择 `encrypt` 或 `decrypt` 方向。
3. 使用尚未重复的 `tcId`。
4. 填写正好 16 byte 的密钥。
5. CBC 填写正好 16 byte 的 IV。
6. 确保明文和密文长度相同，并且都是 16 byte 的整数倍。
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

### 13.3 CBC 缺少 IV

CBC 测试必须提供 16 byte 的 `iv`。ECB 不使用 IV，也不应出现 `iv` 字段。

### 13.4 明文不是整分组

当前关闭 padding。SM4 明文和密文必须是：

```text
16、32、48、64 ... byte
```

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
- 当前固定 IV 仅用于可重复实验，不代表生产系统应固定 IV。
- 当前 SM4 执行器没有 padding，不能直接处理任意长度文本和文件。
- 测试向量通过只证明所测试输入输出一致，不代表整个实现经过安全认证。
- 不要在仓库、JSON、命令历史或测试代码中保存真实生产密钥。

## 15. 推荐日常流程

每次修改后依次运行：

```powershell
python runner.py vectors\sm3.json
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
4. 增加 GmSSL 后端。
5. 研究 HMAC-SM3。
6. 设计带 padding、随机 IV 和完整性认证的文件加密实验。
7. 增加 SM2 密钥生成、签名、验签和加解密实验。
8. 逐步适配更接近 ACVP 的 JSON 能力描述与结果格式。
