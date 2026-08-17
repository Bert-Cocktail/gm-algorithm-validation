# HMAC-SM3 实验记录

## 1. 实验目标

普通 SM3 摘要只能描述消息内容，不能证明消息来自持有某个密钥的一方。本实验通过 OpenSSL 实现 HMAC-SM3，用于生成和验证带密钥的消息认证 tag。

```text
密钥 + 消息 -> HMAC-SM3 -> 256 bit tag
```

## 2. 当前接口

先生成原始二进制密钥文件：

```powershell
python gmcrypto.py generate-hmac-key --output local.hmackey
```

默认生成 32 byte 随机密钥。也可使用 `--bytes` 指定 1 至 4096 byte；`.hmackey` 中保存的是原始字节，不是十六进制文本。

生成文本的 tag：

```powershell
python gmcrypto.py hmac-sm3 --key-file local.hmackey --text "abc"
```

十六进制消息：

```powershell
python gmcrypto.py hmac-sm3 --key-file local.hmackey --hex 616263
```

文件输入：

```powershell
python gmcrypto.py hmac-sm3 --key-file local.hmackey --file examples\message.txt
```

## 3. 验证 tag

```powershell
python gmcrypto.py hmac-sm3 --key-file local.hmackey --text "abc" --verify <64个十六进制字符的tag>
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

当前 `vectors/hmac-sm3.json` 包含 4 个回归向量，运行结果为 `4/4` 通过：原有 16 byte 密钥向量，以及 1、64、65 byte 全零密钥边界向量。所有 tag 来自 OpenSSL 1.1.1i，并已使用 Python gmssl 3.2.2 交叉验证；它们不属于本项目声称的官方标准向量。

HMAC-SM3 的分组长度为 64 byte。1 byte 全零密钥会补零到 64 byte，因此与 64 byte 全零密钥得到相同 tag；65 byte 密钥超过分组长度，会先经过 SM3 压缩，结果随之改变。

当前 13 项 HMAC-SM3 CLI 测试除原有生成、验证和输入校验外，还覆盖：

| 测试 | 结果 |
|---|---|
| 原始二进制密钥文件生成 tag | 通过 |
| 随机生成 32 byte 密钥文件 | 通过 |
| 空密钥文件拒绝 | 通过 |
| 缺失密钥文件拒绝 | 通过 |
| 非法生成长度拒绝 | 通过 |

全仓库测试结果：

```text
Ran 183 tests in ...

OK
```

## 6. 安全说明

- HMAC 密钥应来自安全随机源，不应使用易猜密码。
- 本实验允许不同长度的非空密钥；实际应用建议遵循具体协议的密钥长度要求。
- 推荐使用放在仓库外的原始二进制密钥文件；`*.hmackey` 已加入 `.gitignore`。
- `--key-hex` 仅为兼容旧命令保留，会进入 shell 历史和进程参数。
- 不要把真实生产密钥写入 README、测试代码、JSON 或 Git。
- 接收方必须先验证 tag，再信任或处理消息。
- HMAC-SM3 提供消息认证和完整性，不提供消息机密性。

## 7. 当前限制

- 当前密钥文件不是操作系统安全密钥库，程序也不会自动设置或审计文件访问权限。
- 当前 tag 固定使用完整 32 byte，不支持截断 tag。
- 当前测试 tag 由 OpenSSL 1.1.1i 得到，并已使用 Python gmssl 3.2.2 交叉验证。
