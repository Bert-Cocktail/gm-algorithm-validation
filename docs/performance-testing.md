# 国密算法性能测试实验

## 实验目标

`benchmark.py` 用统一流程测量 OpenSSL 与 Python GmSSL 后端，覆盖：

- SM3 摘要
- HMAC-SM3
- SM4-CTR 加密
- SM2 随机加密
- SM2 私钥解密

性能测试用于观察消息大小、后端和算法类型对运行时间的影响，不是密码算法正确性证明、认证结果或不同机器之间的排名依据。

## 运行方法

完整运行：

```powershell
python benchmark.py --backend both --iterations 10 --warmup 2
```

快速检查：

```powershell
python benchmark.py --backend gmssl --quick
```

自定义消息长度和输出位置：

```powershell
python benchmark.py `
  --backend openssl `
  --sizes 16,1024,1048576 `
  --iterations 20 `
  --warmup 3 `
  --json results\benchmark.json `
  --markdown reports\benchmark.md
```

## 测量方法

每项操作先执行预热，再使用 `time.perf_counter_ns()` 测量指定轮数。JSON 报告记录：

- 平均耗时与中位数耗时
- 每秒操作数
- MiB/s 吞吐率
- Python、操作系统与 OpenSSL 版本
- 消息长度、预热次数和正式迭代次数

SM2 固定使用 32 字节实验消息，避免把消息长度扫描与高成本公钥操作混在一起。SM2 加密每轮生成新的随机密文；解密基准先生成一份有效密文，再重复测量解密。

## 结果解释

仓库中的 [benchmark.md](../reports/benchmark.md) 是一次本机测量。若 OpenSSL 构建缺少某项国密操作，该项标记为 `skipped` 并保留原因，不用零值或 GmSSL 结果冒充 OpenSSL 数据。

为了获得更稳定的数据，应关闭高负载程序、使用固定电源模式、增加迭代次数，并至少重复运行三次。CI 只适合检查工具能否运行，不适合设置固定性能阈值，因为共享运行器的硬件和负载会变化。
