# GM Algorithm Validation 实验报告

生成时间：2026-08-16T09:44:13.451333Z

## 环境

| 项目 | 版本或标识 |
|---|---|
| Python | 3.9.1 |
| OpenSSL | OpenSSL 1.1.1i  8 Dec 2020 |
| gmssl | 3.2.2 |
| Git HEAD | 60e9733 |

## 回归向量验证

- 后端：`cross`
- 状态：`passed`
- 文件：4
- 测试：53
- 通过：53
- 失败：0

## ACVP 风格请求处理

- 后端：`cross`
- 状态：`passed`
- 请求文件：3
- 测试：5
- 后端不一致：0

## 请求清单

| 文件 | SHA-256 | vsId | 算法 | 测试数 |
|---|---|---:|---|---:|
| hmac-sm3-request.json | `df4be633ad067f0b4fde80c484695e534413ed9ef58f1c437265158e8899816a` | 2 | HMAC-SM3 | 1 |
| sm3-request.json | `2e340f88a62d2aa3f6344b4c1971963d5a19dd1dd41956b519ae1d209b41723d` | 1 | SM3 | 2 |
| sm4-request.json | `ae1c93d9e9596463d782bfef960ae359f4810358a4ae2e771deabe454bb4e5cc` | 3 | SM4 | 2 |

## 结论与范围

当前结果证明仓库中的已记录输入在所选本地后端上通过验证，并可通过请求哈希复现实验输入。
本项目不连接 NIST ACVTS，报告不是算法认证证书，也不代表生产安全审计。
SM3/SM4 的 MCT 与 LDT 尚无本项目采用的权威 ACVP 规则，因此当前只执行 AFT。
