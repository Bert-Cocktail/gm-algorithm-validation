# 批量向量验证实验记录

## 实验目标

本阶段将原有单文件 `runner.py` 扩展为批量回归入口。一次命令自动发现并运行全部 JSON 向量，保留每个文件的详细结构化结果，同时生成适合每日检查和归档的总汇报告。

## 使用方法

运行项目全部向量并使用 OpenSSL/GmSSL 交叉验证：

```powershell
python runner.py --all --backend cross --result-dir results
```

默认向量目录是项目中的 `vectors`。也可以显式指定：

```powershell
python runner.py --all --vector-dir vectors --backend cross --result-dir results
```

`--all` 必须配合 `--result-dir`，不能与单文件参数或 `--result-json` 混用。结果目录不能与向量目录相同。

## 输出文件

当前 6 个向量文件会产生：

```text
results/
├── hmac-sm3-cross.json
├── sm3-cross.json
├── sm4-cross.json
├── sm4-ctr-hmac-sm3-cross.json
└── summary.json
```

逐文件报告沿用结构化结果格式，包含算法、后端、每个 `tcId` 的状态和 expected/actual。

总汇报告主要字段为：

```json
{
  "schemaVersion": 1,
  "backend": "cross",
  "status": "passed",
  "exitCode": 0,
  "summary": {
    "files": 4,
    "passedFiles": 4,
    "failedFiles": 0,
    "errorFiles": 0,
    "tests": 64,
    "passedTests": 64,
    "failedTests": 0
  },
  "files": []
}
```

`files` 数组保存每个向量文件、结果文件、算法、状态、退出码和局部汇总。`tests` 只统计成功完成校验的向量用例；输入无效或环境错误的文件使用 `errorFiles` 单独计数。

## 继续执行与退出码

程序不会因为一个文件失败就停止：

- 全部文件通过：退出码 `0`。
- 至少一个测试结果不匹配：退出码 `1`。
- 至少一个输入、依赖、环境或结果写入错误：退出码 `2`。

退出码 `2` 的优先级高于 `1`。即使出现错误，已经发现的其余向量文件仍会继续执行并生成报告。

## 测试覆盖

新增 5 项批量运行测试：

- 六个向量文件生成逐文件报告与总汇。
- 测试结果失败后继续执行后续文件。
- 输入错误后继续执行，并使总退出码为 `2`。
- GmSSL 批量模式不查找 OpenSSL。
- 拒绝让结果目录与向量目录相同。

全仓库测试结果：

```text
Ran 183 tests in ...

OK
```

## 当前结果

当前批量交叉验证覆盖 64 个向量：SM2 签名 6 个、SM2 加密与格式 5 个、SM3 15 个、HMAC-SM3 4 个、SM4 28 个、认证组合 6 个。六个文件均通过对应 OpenSSL 后端与 Python gmssl 3.2.2 验证；SM2 使用支持签名和加密接口的 OpenSSL 3。
