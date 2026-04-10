# Protocol Packages

`crypto/protocol/` 用来放置建立在基础密码原语之上的通用协议层能力。

当前已提供：

- `tmps`
  - BN254 元素、标量、proof input 的稳定结构
  - `legacyv1` 编码
  - challenge 生成、hash helper、pairing verify plan
- `pre`
  - 通用 trusted-proxy 重加密封装
  - payload / token / recipient / message 的稳定编码与哈希
- `post`
  - `Strict` / `LegacyCompat` 两套 profile
  - challenge / prove / verify / hash / 稳定编码

这些包的目标是：

- 只沉淀**可复用的协议层能力**
- 避免把上层业务字段直接塞进密码库
- 通过 testdata 和 golden vectors 固定跨语言字节行为

如果你只是要钱包、地址、KEM 或 PQ 签名，请优先使用 `walletcrypto`。

如果你需要 EVM 兼容消息哈希、恢复地址或结构化 JSON 规范化，请分别使用：

- `crypto/evm`
- `crypto/encoding/canonical`
