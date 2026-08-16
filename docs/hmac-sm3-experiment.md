# HMAC-SM3 实验记录

## 1. 实验目标

普通 SM3 摘要只能描述消息内容，不能证明消息来自持有某个密钥的一方。本实验通过 OpenSSL 实现 HMAC-SM3，用于生成和验证带密钥的消息认证 tag。

```text
密钥 + 消息 -> HMAC-SM3 -> 256 bit tag
```

## 2. 当前接口

生成文本的 tag：

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --text "abc"
```

输出：

```text
0933617a88d312f6f9fb4b5f200e31a64d655e92f7fa2a43f55dfeeb8ab6788d
```

十六进制消息：

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --hex 616263
```

文件输入：

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --file examples\message.txt
```

## 3. 验证 tag

```powershell
python gmcrypto.py hmac-sm3 --key-hex 00112233445566778899aabbccddeeff --text "abc" --verify 0933617a88d312f6f9fb4b5f200e31a64d655e92f7fa2a43f55dfeeb8ab6788d
```

正确结果：

```text
OK
退出码 0
```

消息、密钥或 tag 不匹配：

```text
FAIL
退出码 1
```

程序使用 Python `hmac.compare_digest()` 进行恒定时间比较，避免直接使用普通字符串相等比较。

## 4. OpenSSL 调用

底层调用形式为：

```text
openssl dgst -sm3 -mac HMAC -macopt hexkey:<key> -binary
```

文本、十六进制和文件输入都会先转换为原始字节，再通过标准输入传给 OpenSSL。这样 `gmcrypto.py` 和 JSON 向量执行器能够复用同一个底层 HMAC-SM3 函数。

## 5. 测试结果

统一向量入口：

```powershell
python runner.py vectors\hmac-sm3.json
```

当前 `vectors/hmac-sm3.json` 包含 1 个回归向量，运行结果为 `1/1` 通过。该 tag 来自 OpenSSL 1.1.1i，并已使用 Python gmssl 3.2.2 交叉验证；它不属于本项目声称的官方标准向量。

新增 8 项测试：

| 测试 | 结果 |
|---|---|
| 文本 `abc` 生成 tag | 通过 |
| 十六进制 `616263` 生成相同 tag | 通过 |
| 文件输入生成 tag | 通过 |
| 正确 tag 验证 | 通过 |
| 修改消息后验证失败 | 通过 |
| 非法十六进制密钥 | 通过 |
| 空密钥拒绝 | 通过 |
| 错误 tag 长度拒绝 | 通过 |

全仓库测试结果：

```text
Ran 106 tests in ...

OK
```

## 6. 安全说明

- HMAC 密钥应来自安全随机源，不应使用易猜密码。
- 本实验允许不同长度的非空密钥；实际应用建议遵循具体协议的密钥长度要求。
- `--key-hex` 会进入 shell 历史和进程参数，因此只适合学习实验。
- 不要把真实生产密钥写入 README、测试代码、JSON 或 Git。
- 接收方必须先验证 tag，再信任或处理消息。
- HMAC-SM3 提供消息认证和完整性，不提供消息机密性。

## 7. 当前限制

- 当前没有密钥文件、环境变量或安全密钥存储接口。
- 当前 tag 固定使用完整 32 byte，不支持截断 tag。
- 当前测试 tag 由 OpenSSL 1.1.1i 得到，并已使用 Python gmssl 3.2.2 交叉验证。
