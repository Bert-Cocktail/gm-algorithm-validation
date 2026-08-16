# SM3/SM4 MCT 规则调研

调研日期：2026-08-16

## 目标

确认能否把 NIST ACVP 中的 Monte Carlo Test（MCT）直接用于本仓库的 SM3 或 SM4，并决定是否实现。

## 权威资料

本次读取 NIST 官方 `usnistgov/ACVP` 仓库中的 SHA 规范。引用固定到提交 `892fd14710f3a7edbea230d0aecc5511e0257f8e`（提交时间 2026-08-14）：

- [Supported Hash Algorithms](https://github.com/usnistgov/ACVP/blob/892fd14710f3a7edbea230d0aecc5511e0257f8e/src/sha/sections/03-supported.adoc)
- [Test Types and Test Coverage](https://github.com/usnistgov/ACVP/blob/892fd14710f3a7edbea230d0aecc5511e0257f8e/src/sha/sections/04-testtypes.adoc)
- [Test Groups and Test Cases](https://github.com/usnistgov/ACVP/blob/892fd14710f3a7edbea230d0aecc5511e0257f8e/src/sha/sections/06-test-vectors.adoc)
- [ACVP source tree](https://github.com/usnistgov/ACVP/tree/892fd14710f3a7edbea230d0aecc5511e0257f8e/src)

## 查证结果

SHA 规范明确列出的算法是 SHA-1 和 SHA2-224/256/384/512 等 SHA-2 变体，不包含 SM3。该规范定义三类测试：

- `AFT`：普通算法功能测试。
- `MCT`：100 组外循环，每组包含 1000 次链式摘要。
- `LDT`：Large Data Test，用重复内容表达多 GB 消息。

SHA-1/SHA-2 的标准 MCT 使用三个状态值 `A/B/C`，每轮摘要 `A || B || C`，并把输出移动回状态；2023 年更新后还定义了 `standard` 和 `alternate` 两种 `mctVersion`。这些规则在规范正文中明确限定为 SHA-1 和 SHA-2。

NIST ACVP 官方源码目录中未发现 SM3 或 SM4 的算法规范目录。因此：

1. 不能仅因 SM3 也是 256 bit 摘要，就把 SHA2-256 MCT 循环称为 SM3 的正式 ACVP MCT。
2. 不能把 AES 等分组密码的 MCT 规则直接套到 SM4，并声称得到正式 SM4 ACVP MCT。
3. 本次未找到可由项目采用的公开权威 SM3/SM4 ACVP MCT 请求、迭代和响应规范。

这里的结论是“本次权威资料范围内未找到”，不是断言任何组织都不存在其他内部或后续规范。

## 项目决定

- 继续执行 `AFT`。
- Schema 识别 `MCT` 与 `LDT`，能力描述标记为 `recognized-not-implemented`。
- 收到 MCT/LDT 请求时返回输入错误，不进行伪实现。
- 不再使用此前不准确的 `GDT` 名称。
- 将来只有在确定具体标准、版本、算法标识、请求字段、迭代伪代码和响应字段后，才增加独立实现与权威测试向量。

## 后续实现门槛

实现正式 MCT 前至少需要：

1. 明确规范发布机构和稳定文档版本。
2. 确认规范明确覆盖 SM3 或 SM4。
3. 固定种子、循环次数、状态更新、字节序和输出字段。
4. 获得至少一组独立已知答案用于交叉验证。
5. 为 OpenSSL 与 GmSSL 后端分别运行，并收集全部不一致。
