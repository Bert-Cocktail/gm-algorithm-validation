# SM4-CTR + HMAC-SM3 加密认证实验

## 实验目标

本实验使用 Encrypt-then-MAC 组合 SM4-CTR 与 HMAC-SM3：先加密明文，再认证版本、算法、IV 和密文；接收方只有在 tag 验证成功后才允许解密。

## 双密钥规则

实验固定使用两把独立密钥：

- SM4 密钥：16 byte，用于 SM4-CTR 加密和解密。
- HMAC 密钥：32 byte，用于 HMAC-SM3 认证。

测试中的固定密钥是公开实验数据。实际密钥应由安全随机源生成，不得写入仓库，也不能把同一把密钥同时用于加密和认证。

生成随机实验密钥的命令：

```powershell
openssl rand -hex 16
openssl rand -hex 32
```

## 数据包格式

第一版使用便于观察的 JSON 对象：

```json
{
  "version": 1,
  "algorithm": "SM4-CTR-HMAC-SM3",
  "iv": "000102030405060708090a0b0c0d0e0f",
  "ciphertext": "...",
  "tag": "..."
}
```

`iv` 固定为 16 byte，`tag` 固定为完整的 32 byte HMAC-SM3。`ciphertext` 允许为空，以便后续覆盖空明文实验。程序拒绝缺失字段和未知字段，避免未被认证的附加信息产生歧义。

## HMAC 输入编码

程序不直接认证 JSON 文本，因为空格、换行和字段顺序会改变 JSON 字节。认证数据固定编码为：

```text
ASCII("GMENC")
|| version 的 1 byte
|| ASCII("SM4-CTR-HMAC-SM3")
|| 16 byte IV
|| 8 byte 密文长度（无符号大端序）
|| 密文字节
```

因此版本、算法、IV 和密文全部受到 HMAC 保护。`tag` 本身不加入 HMAC 输入。

对应代码位于 `authenticated_sm4.py`：

- `validate_keys()`：校验并规范化两把密钥。
- `validate_package()`：校验并规范化 JSON 数据包。
- `build_authenticated_data()`：构造唯一的认证字节序列。
- `package_authenticated_data()`：从数据包得到认证字节序列。
- `encrypt_and_authenticate()`：生成随机 IV，使用 SM4-CTR 加密，再计算 HMAC-SM3。
- `verify_and_decrypt()`：恒定时间比较 tag，成功后才使用 SM4-CTR 解密。

组合向量执行器位于 `authenticated_sm4_runner.py`。统一 `runner.py` 根据根字段 `algorithm: "SM4-CTR-HMAC-SM3"` 分派到该模块，同时检查预期密文、tag 和解密恢复明文。

## 加密认证流程

```text
明文 + SM4 key + 随机 IV
        -> SM4-CTR
        -> 密文
版本 + 算法 + IV + 密文
        -> HMAC-SM3(HMAC key)
        -> tag
```

测试允许显式传入固定 IV 以生成可重复向量。普通调用不传 IV，由 `secrets.token_bytes(16)` 生成。

## 验证解密流程

```text
校验数据包结构
-> 重建认证数据
-> 计算并恒定时间比较 tag
-> tag 不匹配：authentication failed，停止
-> tag 匹配：执行 SM4-CTR 解密
```

测试使用 mock 验证了 tag 错误时解密函数不会被调用。

## 固定回归向量

`vectors/sm4-ctr-hmac-sm3.json` 当前包含 1 个固定实验向量：

```text
明文: 616263
IV:   000102030405060708090a0b0c0d0e0f
密文: 67faff
tag:  3c08e5f08855380ee0fbabd47aed4dbae5db19ebbe7b001a42fa8c69aaf97ade
```

该结果由 OpenSSL 1.1.1i 生成，并已使用 Python gmssl 3.2.2 交叉验证。它仍是实验向量，不属于官方标准向量。

运行组合向量：

```powershell
python runner.py vectors\sm4-ctr-hmac-sm3.json
```

预期结果：

```text
[PASS] tcId=1 algorithm=SM4-CTR-HMAC-SM3

Total: 1, Passed: 1, Failed: 0
```

## 当前测试

运行本阶段测试：

```powershell
python -m unittest tests.test_authenticated_sm4 -v
```

当前共有 21 项认证 SM4 核心测试和 6 项组合向量执行器测试，覆盖密钥长度、格式编码、固定向量、空消息、非整分组消息、随机 IV、往返解密、向量校验，以及 IV、密文、tag 和密钥篡改。

全量测试结果：

```text
Ran 95 tests in ...

OK
```

## 安全结论

- SM4 密钥与 HMAC 密钥用途分离。
- 同一 SM4 密钥下不能重复 CTR IV/初始计数器。
- HMAC 覆盖版本、算法、IV、密文长度和密文。
- 修改 IV、密文或 tag 都会导致认证失败。
- HMAC 认证成功只说明 HMAC 密钥正确，不能单独检测调用方传入了错误的 SM4 密钥；两把密钥必须由同一套可靠密钥管理流程提供。
- 合法格式下的 tag 不匹配统一报告为 `authentication failed`，并且认证失败时不解密。不支持的版本、算法或非法字段长度作为格式错误提前拒绝。

当前格式是学习实验格式，没有经过标准化、互操作验证或安全审计，不能直接作为生产协议使用。
