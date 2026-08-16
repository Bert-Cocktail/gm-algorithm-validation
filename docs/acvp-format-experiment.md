# 本地 ACVP 风格请求与响应实验

## 实验目标

现有 `vectors/*.json` 同时保存输入和预期结果，适合本地回归测试。本实验新增 `acvp_adapter.py`，把输入请求与计算响应分开，并采用接近 ACVP 的 `acvVersion`、`vsId`、`testGroups`、`tgId` 和 `tcId` 层级。

这是本地格式与处理流程实验。程序不连接 NIST ACVTS，不实现注册、能力协商、会话认证或结果上传，也不能生成认证证书。

## 运行方法

仓库提供 SM3 请求样例：

```powershell
python acvp_adapter.py acvp\requests\sm3-request.json --output results\sm3-response.json
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
| `SM3` | `msg`, `msgLen` | `md` |
| `HMAC-SM3` | `key`, `msg`, `msgLen` | `mac` |
| `SM4` | 组级 `mode`, `direction`；测试级 `key`, `iv`, `pt` 或 `ct` | 加密返回 `ct`，解密返回 `pt` |
| `SM4-CTR-HMAC-SM3` | `sm4Key`, `hmacKey`, `iv`, `pt` | `ct`, `tag` |

SM4 的 ECB 组不需要 `iv`；CBC 和 CTR 需要 128 bit IV。SM4-CTR-HMAC-SM3 是本项目的实验组合，不是这里声称的 ACVP 标准算法标识。

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

`tests/test_acvp_adapter.py` 包含 6 项测试，覆盖 SM3、HMAC-SM3、SM4 加解密、认证组合、重复 ID 与覆盖保护，以及多个交叉后端不一致的完整收集。

```powershell
python -m unittest tests.test_acvp_adapter -v
```
