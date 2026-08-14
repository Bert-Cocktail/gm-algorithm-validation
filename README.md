# GM Algorithm Validation Lab

这是一个面向国密算法学习的实验仓库。当前阶段使用 OpenSSL 作为密码算法后端，按照“测试向量输入、算法计算、预期结果比较、输出 PASS/FAIL”的流程验证 SM3。

项目未从零实现密码算法。后续计划在相同测试框架中逐步加入 GmSSL 后端、SM4 和 SM2。

## 当前功能

- 使用 OpenSSL 计算 SM3 摘要
- 读取简化 ACVP 风格的 JSON 测试向量
- 校验 `algorithm`、`tcId`、`msg`、`msgLen` 和 `md`
- 输出每个测试用例的 PASS/FAIL 及汇总结果
- 区分测试失败和输入/环境错误
- 使用 Python `unittest` 测试执行器自身

当前尚未实现：GmSSL 后端、C API、SM2、SM4、性能测试和 ACVTS 接入。

## 项目结构

```text
gm-algorithm-validation/
├── README.md
├── runner.py
├── vectors/
│   └── sm3.json
├── tests/
│   └── test_sm3.py
├── examples/
│   └── message.txt
├── docs/
│   └── sm3-experiment.md
└── results/
```

## 环境要求

- Windows PowerShell
- Python 3
- 支持 SM3 的 OpenSSL

本次实验实际使用：

```text
OpenSSL 1.1.1i  8 Dec 2020
```

检查环境：

```powershell
python --version
openssl version
openssl list -digest-algorithms | Select-String SM3
```

## 运行 SM3 测试向量

在 PowerShell 中进入仓库：

```powershell
cd C:\Users\16256\Documents\密码学\gm-algorithm-validation
```

执行测试向量：

```powershell
python runner.py vectors\sm3.json
```

当前预期输出：

```text
[PASS] tcId=1

Total: 1, Passed: 1, Failed: 0
```

如果 OpenSSL 没有加入 `PATH`，可以显式指定程序路径：

```powershell
python runner.py vectors\sm3.json --openssl "C:\path\to\openssl.exe"
```

退出码约定：

- `0`：所有测试向量通过
- `1`：至少一个摘要与预期结果不一致
- `2`：测试向量、参数或 OpenSSL 环境有误

## 运行单元测试

运行全部单元测试：

```powershell
python -m unittest discover -s tests -v
```

当前共有 9 项测试，覆盖：

- `abc` 标准向量
- 空消息
- `abcd` 重复 16 次的长消息
- 大写十六进制规范化
- 奇数长度十六进制拒绝
- 非十六进制字符拒绝
- `msgLen` 不匹配拒绝
- 错误摘要返回测试失败
- OpenSSL 缺失时给出明确错误

本次实测结果：

```text
Ran 9 tests in ...

OK
```

## 文件摘要实验

计算示例文件的 SM3：

```powershell
openssl dgst -sm3 examples\message.txt
```

当前版本文件的实测摘要为：

```text
e80350db1655830b92331fcfbb96802446fd435dfc54e6f95bba552b9390f26d
```

修改 `message.txt` 中任意一个字符后再次计算，可以观察摘要发生显著变化。恢复原文件后，摘要也应恢复为原值。详细过程参见 [SM3 实验记录](docs/sm3-experiment.md)。

## 测试向量格式

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
- `tcId`：测试用例编号

当前标准向量在文件中标注来源为 `GB/T 32905-2016`。测试向量的预期结果应来自正式标准或可信实现，不应由待测程序自行生成。

## 下一步计划

1. 在正式 JSON 向量文件中增加空消息和长消息。
2. 使用 OpenSSL EVP API 编写 C 语言 SM3 程序。
3. 让同一批测试向量同时验证命令行后端和 C 后端。
4. 增加 GmSSL 后端，再扩展到 SM4 和 SM2。
