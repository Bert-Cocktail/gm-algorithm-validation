# Cryptographic Performance Report

Generated: `2026-08-17T08:33:06.884279Z`

Results are local measurements, not certification or cross-machine performance guarantees.

| Backend | Operation | Bytes | Status | Median ms | Ops/s | MiB/s |
|---|---|---:|---|---:|---:|---:|
| gmssl | SM3 | 16 | measured | 0.35105 | 2848.597 | 0.043 |
| gmssl | HMAC-SM3 | 16 | measured | 0.88765 | 1126.57 | 0.017 |
| gmssl | SM4-CTR-encrypt | 16 | measured | 0.10155 | 9847.366 | 0.15 |
| gmssl | SM3 | 1024 | measured | 4.1902 | 238.652 | 0.233 |
| gmssl | HMAC-SM3 | 1024 | measured | 4.71745 | 211.979 | 0.207 |
| gmssl | SM4-CTR-encrypt | 1024 | measured | 6.2767 | 159.319 | 0.156 |
| gmssl | SM2-encrypt | 32 | measured | 6.93555 | 144.185 | 0.004 |
| gmssl | SM2-decrypt | 32 | measured | 0.86945 | 1150.152 | 0.035 |
