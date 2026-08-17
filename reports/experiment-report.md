# GM Algorithm Validation 实验报告

生成时间：2026-08-17T07:28:54.737141Z

## 环境

| 项目 | 版本或标识 |
|---|---|
| Python | 3.9.1 |
| OpenSSL | OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025) |
| gmssl | 3.2.2 |
| Git HEAD | 7a33c5e |

## 回归向量验证

- 后端：`cross`
- 状态：`passed`
- 文件：6
- 测试：64
- 通过：64
- 失败：0

## ACVP 风格请求处理

- 后端：`cross`
- 状态：`passed`
- 请求文件：4
- 测试：9
- 后端不一致：0

## 请求清单

| 文件 | SHA-256 | vsId | 算法 | 测试数 |
|---|---|---:|---|---:|
| hmac-sm3-request.json | `df4be633ad067f0b4fde80c484695e534413ed9ef58f1c437265158e8899816a` | 2 | HMAC-SM3 | 1 |
| sm2-request.json | `d126e0920c2bdc5c24274d634236895236c9ea30ff10eb809ed17da7f14295ea` | 4 | SM2 | 4 |
| sm3-request.json | `2e340f88a62d2aa3f6344b4c1971963d5a19dd1dd41956b519ae1d209b41723d` | 1 | SM3 | 2 |
| sm4-request.json | `ae1c93d9e9596463d782bfef960ae359f4810358a4ae2e771deabe454bb4e5cc` | 3 | SM4 | 2 |

## 能力快照

| 本地算法 | 标准或实验说明 | 操作 | ACVP 标识状态 |
|---|---|---|---|
| SM2 | GB/T 32918 local verification and decryption experiment | verify, decrypt | no-identifier-asserted |
| SM3 | GB/T 32905-2016 | AFT | no-identifier-asserted |
| HMAC-SM3 | local HMAC construction using SM3 | AFT | no-identifier-asserted |
| SM4 | GB/T 32907-2016 | encrypt, decrypt | no-identifier-asserted |
| SM4-CTR-HMAC-SM3 | local Encrypt-then-MAC experiment | encrypt | local-only |

## 结论与范围

当前结果证明仓库中的已记录输入在所选本地后端上通过验证，并可通过请求哈希复现实验输入。
本项目不连接 NIST ACVTS，报告不是算法认证证书，也不代表生产安全审计。
SM3/SM4 的 MCT 与 LDT 尚无本项目采用的权威 ACVP 规则，因此当前只执行 AFT。
