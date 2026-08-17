# 本地 ACVP 风格请求与响应实验

## 实验目标

现有 `vectors/*.json` 同时保存输入和预期结果，适合本地回归测试。本实验新增 `acvp_adapter.py`，把输入请求与计算响应分开，并采用接近 ACVP 的 `acvVersion`、`vsId`、`testGroups`、`tgId` 和 `tcId` 层级。

这是本地格式与处理流程实验。程序不连接 NIST ACVTS，不实现注册、能力协商、会话认证或结果上传，也不能生成认证证书。

## 运行方法

仓库在 `acvp/requests` 与 `acvp/responses` 中提供 SM2、SM3、HMAC-SM3 和 SM4 请求与响应样例：

```powershell
python acvp_adapter.py acvp\requests\sm3-request.json --output results\sm3-response.json
python acvp_adapter.py acvp\requests\hmac-sm3-request.json --output results\hmac-sm3-response.json
python acvp_adapter.py acvp\requests\sm4-request.json --output results\sm4-response.json
python acvp_adapter.py acvp\requests\sm2-request.json --output results\sm2-response.json --backend cross --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
```

选择后端：

```powershell
python acvp_adapter.py acvp\requests\sm3-request.json --output results\sm3-response.json --backend openssl
python acvp_adapter.py acvp\requests\sm3-request.json --output results\sm3-response.json --backend gmssl
python acvp_adapter.py acvp\requests\sm3-request.json --output results\sm3-response.json --backend cross
```

输出目录必须已经存在，输出文件不能与请求文件相同。响应采用同目录临时文件原子替换。

## SM3 请求与响应

请求不包含预期摘要：

```json
[
  {"acvVersion": "1.0"},
  {
    "vsId": 1,
    "algorithm": "SM3",
    "testGroups": [
      {
        "tgId": 1,
        "testType": "AFT",
        "tests": [
          {"tcId": 1, "msg": "616263", "msgLen": 24}
        ]
      }
    ]
  }
]
```

响应返回 `md`：

```json
[
  {"acvVersion": "1.0"},
  {
    "vsId": 1,
    "algorithm": "SM3",
    "testGroups": [
      {
        "tgId": 1,
        "tests": [
          {
            "tcId": 1,
            "md": "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
          }
        ]
      }
    ]
  }
]
```

## 支持的算法字段

| `algorithm` | 请求主要字段 | 响应字段 |
|---|---|---|
| `SM2` | 组级 `operation`；验签输入 ID、消息、公钥、DER 签名，解密输入私钥和密文 | `testPassed`，解密成功时返回 `pt` |
| `SM3` | `msg`, `msgLen` | `md` |
| `HMAC-SM3` | `key`, `msg`, `msgLen` | `mac` |
| `SM4` | 组级 `mode`, `direction`；测试级 `key`, `iv`, `pt` 或 `ct` | 加密返回 `ct`，解密返回 `pt` |
| `SM4-CTR-HMAC-SM3` | `sm4Key`, `hmacKey`, `iv`, `pt` | `ct`, `tag` |

SM4 的 ECB 组不需要 `iv`；CBC 和 CTR 需要 128 bit IV。SM4-CTR-HMAC-SM3 是本项目的实验组合，不是这里声称的 ACVP 标准算法标识。

SM2 当前只提供可重复复核的 `verify` 和 `decrypt`。随机加密每次会产生不同密文，因此没有直接加入按字节比较的 `--verify-responses` 流程。样例请求中的私钥是公开的测试专用 `d=1`，不得替换为或提交真实业务私钥。

组级 `testType` 可写为 `AFT`、`MCT` 或 `LDT`。当前只有 `AFT` 具备正确执行逻辑；`MCT` 与 `LDT` 会被识别并明确拒绝为“尚未实现”，不会套用普通 AFT 计算。HMAC-SM3 组还声明 `keyLen` 与 `macLen`，SM4 组声明 `direction`、`keyLen` 与 `mode`。`msgLen` 位于具体测试用例中，因为同一组可以包含不同长度的消息。MCT 调研见 [SM3/SM4 MCT 规则调研](mct-research.md)。

## JSON Schema 校验

请求执行前使用 `acvp/schemas/request-schema.json` 校验，响应写入前使用 `acvp/schemas/response-schema.json` 校验，能力描述和批量汇总分别使用 `capabilities-schema.json`、`batch-summary-schema.json`。四份 Schema 使用 Draft 2020-12 声明，并由开发依赖 `jsonschema 4.25.1` 的完整 Draft 2020-12 验证器执行。

## 能力描述

运行：

```powershell
python acvp_adapter.py --capabilities
```

输出包含五种算法的 `revision`、`testTypes` 和长度限制，以及 SM2 的曲线、操作和编码格式、SM4 的模式与方向。处理请求时会实际使用这些约束。

每项算法还包含 `identifierMapping`：

- `localAlgorithm`：仓库内部路由名称。
- `standardIdentifier`：算法或实验构造的来源说明。
- `acvpAlgorithm`：正式 ACVP 算法标识；当前均为 `null`。
- `acvpStatus`：未断言标识或仅限本地实验的原因。

这里不把 `SM3`、`SM4` 等本地字符串冒充为 NIST ACVP 注册标识。`localFormat: true` 明确表示这不是发送到 ACVTS 的正式注册对象。

## 批量请求处理

```powershell
python acvp_adapter.py --all `
  --request-dir acvp\requests `
  --response-dir results\acvp `
  --backend cross
```

批量模式只读取 `*-request.json`，自动创建响应目录，按文件名顺序继续处理全部请求。每个成功请求产生对应的 `*-response.json`，目录中同时生成 `summary.json`：

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
    "tests": 9,
    "backendMismatches": 0
  },
  "files": []
}
```

跨请求文件的 `vsId` 必须唯一。单个文件出现 Schema、参数或重复 ID 错误时，其他文件仍继续；总退出码优先级为错误 `2`、后端不一致 `1`、全部成功 `0`。请求目录和响应目录不能相同。

## 请求清单与响应复核

生成可追溯 manifest：

```powershell
python acvp_manifest.py --request-dir acvp\requests --output results\acvp\manifest.json
```

清单按文件名排序，记录每个请求的 SHA-256、字节数、`vsId`、算法和测试数量，并使用 `manifest-schema.json` 校验。输入发生任何字节变化都会改变哈希。

重新计算并复核响应：

```powershell
python acvp_adapter.py --verify-responses `
  --request-dir acvp\requests `
  --response-dir results\acvp `
  --backend cross
```

响应内容不同返回退出码 `1`；响应缺失、格式错误或请求无效返回 `2`。所有文件均会继续检查。

## 归档报告与持续集成

`experiment_report.py` 读取回归向量汇总、ACVP 汇总和 manifest，生成 Markdown 报告：

```powershell
python experiment_report.py `
  --vector-summary results\summary.json `
  --acvp-summary results\acvp\summary.json `
  --manifest results\acvp\manifest.json `
  --capabilities results\acvp\capabilities.json `
  --output reports\experiment-report.md
```

报告记录 Python、OpenSSL、gmssl、Git 提交、通过率、请求哈希和能力快照，并保留非认证范围说明。CI 自动归档结构化回归结果、四份请求响应、能力 JSON、manifest 和 Markdown 报告。

## 交叉后端诊断

选择 `--backend cross` 时，两套后端都会运行。若结果不一致，程序继续处理后续测试，使用 OpenSSL 结果完成响应，并返回退出码 `1`。响应额外包含：

```json
"localDiagnostics": {
  "backend": "cross",
  "mismatches": [
    {
      "tcId": 1,
      "operation": "SM3",
      "openssl": "...",
      "gmssl": "..."
    }
  ]
}
```

`localDiagnostics` 是本项目扩展，只用于定位实现差异，不属于可提交给 ACVTS 的响应字段。正常一致时不生成该字段。

## 输入校验与退出码

- `acvVersion` 当前必须为 `1.0`。
- `vsId` 必须为非负整数。
- `tgId` 和 `tcId` 必须为整数且在请求中唯一。
- 每个测试组必须包含非空 `tests` 数组。
- 算法参数沿用现有向量执行器的十六进制、长度、模式和方向校验。
- `0`：响应成功生成，所选后端无不一致。
- `1`：响应成功生成，但交叉后端存在不一致。
- `2`：请求、环境、依赖或响应写入错误。

## 测试覆盖

`tests/test_acvp_adapter.py` 包含 13 项测试，覆盖 SM2 验签与解密、SM3、HMAC-SM3、SM4、认证组合、能力描述与 Schema 等。

`tests/test_acvp_batch.py` 包含 8 项测试，覆盖三类样例批量成功、错误后继续、后端不一致汇总、跨文件重复 `vsId`、目录保护，以及响应复核的成功、篡改和缺失场景。

`tests/test_acvp_manifest.py` 包含 4 项测试，`tests/test_experiment_report.py` 包含 4 项测试。

```powershell
python -m unittest tests.test_acvp_adapter -v
python -m unittest tests.test_acvp_batch -v
python -m unittest tests.test_acvp_manifest -v
python -m unittest tests.test_experiment_report -v
```
