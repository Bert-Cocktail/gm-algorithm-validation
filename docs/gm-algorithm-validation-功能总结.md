# 国密算法验证实验库功能总结

## 项目定位

这是一个用于学习和验证中国商用密码算法的实验仓库。项目不从零实现底层密码算法，而是调用 OpenSSL 和 Python GmSSL，配合 JSON 测试向量、自动化测试和实验记录，检查算法输入输出是否正确。

## 已实现功能

### SM2

- `sm2p256v1` 曲线上的签名和验签。
- PEM 格式密钥生成。
- 公钥加密、私钥解密。
- DER、C1C3C2、C1C2C3 三种密文格式互相转换。
- C3 完整性校验，密文被修改时拒绝输出明文。
- 随机加密回环测试：加密后解密，并确认恢复原文。
- 普通用户命令行操作和 ACVP 风格随机加密请求。

### SM3 与 HMAC-SM3

- 使用 OpenSSL 计算 SM3 摘要。
- 支持空消息、短消息、长消息和边界长度测试向量。
- 使用密钥文件计算和验证 HMAC-SM3。
- 支持文本、十六进制消息和文件输入。

### SM4

- 支持 ECB、CBC、CTR 三种模式。
- 支持加密和解密测试。
- 检查密钥、IV、数据长度和十六进制格式。
- CTR 支持非 16 字节整数倍的数据。
- 当前实验使用无 padding 模式。

### 认证加密实验

- 使用 SM4-CTR 加密数据，再使用 HMAC-SM3 认证。
- 认证失败时不会解密或写出明文。
- 支持随机 IV、篡改检测和密钥文件。
- 该格式属于学习实验格式，尚未作为生产级文件格式使用。

## 验证和工程功能

- `runner.py` 统一运行 SM2、SM3、HMAC-SM3、SM4 和认证加密向量。
- 支持 OpenSSL、GmSSL 和双后端交叉验证。
- 支持批量运行全部向量并生成 JSON 结果和汇总报告。
- 提供 ACVP 风格请求、响应、JSON Schema、能力描述和响应复核。
- 提供性能测试工具，测量 SM2、SM3、HMAC-SM3 和 SM4 的本机运行表现。
- GitHub Actions 自动运行测试、向量验证和快速性能报告。
- 当前完整测试数量为 192 项，另有 1 项会因旧版 OpenSSL 不支持 SM2 签名而按条件跳过。

## 常用命令

```powershell
# 运行全部回归向量
python runner.py --all --backend cross --result-dir results

# 运行 SM2 向量
python runner.py vectors\sm2.json --backend cross
python runner.py vectors\sm2-encryption.json --backend cross

# 运行全部单元测试
python -m unittest discover -s tests -v

# 生成性能报告
python benchmark.py --backend both --iterations 10 --warmup 2
```

## 当前边界

本项目是学习和验证工具，不是经过安全审计的密码产品，也不是正式 ACVTS 客户端。当前尚未实现 C API、通用 padding、生产级认证文件格式和 ACVTS 网络接入。仓库中的测试私钥、固定随机数和示例密钥只用于实验，不能用于真实业务。

