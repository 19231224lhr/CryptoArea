# CryptoArea 密码服务目录

本文整理 `CryptoArea` 当前对外可提供的主要密码服务，便于外部团队快速判断该仓库能否覆盖自己的接入需求。

## 1. 模块分层

| 模块 | 路径 | 角色 |
| --- | --- | --- |
| 主密码模块 | `github.com/19231224lhr/CryptoArea/crypto` | 对外推荐接入入口 |
| PQ 底层模块 | `github.com/19231224lhr/CryptoArea/pqcgo` | PQ 签名 / KEM 的底层封装 |
| WASM 模块 | `github.com/19231224lhr/CryptoArea/wasm/crypto` | wasm 侧包装与兼容层 |

## 2. walletcrypto 提供的服务

| 类别 | API | 说明 |
| --- | --- | --- |
| 密钥生成 | `GenerateKeyPair` | 支持经典签名与 PQ 签名 |
| 确定性密钥生成 | `GenerateKeyPairWithSeed` | 支持基于 seed 派生 |
| 签名 | `SignMessage` | 统一签名入口 |
| 验签 | `VerifyMessage` | 统一验签入口 |
| 地址生成 | `GenerateAddress` | 支持 Base58Check / Hash160 Hex / Ethereum Hex |
| KEM 密钥生成 | `GenerateKEMKeyPair` | PQ KEM |
| KEM 封装 | `EncapsulateSharedSecret` | PQ KEM |
| KEM 解封装 | `DecapsulateSharedSecret` | PQ KEM |
| 私钥加密 | `EncryptPrivateKey` | keystore 场景 |
| 私钥解密 | `DecryptPrivateKey` | keystore 场景 |
| 随机数 | `RandomBytes` | 钱包与协议工具 |
| 哈希 | `HashData` | `sha256` / `sha512` / `keccak256` / `ripemd160` / `hash160` |
| HMAC | `HMACSHA256` | 常用消息认证 |
| Seed-chain 初始化 | `NewSeedChain` / `NewSeedChainFromSeed` | 哈希链一次一钥 |
| Seed-chain 恢复 | `RecoverSeedChain` | 基于 root seed 和 step 恢复 |
| Seed-chain 当前锚点 | `(*SeedChain).CurrentAnchor` | 获取当前 anchor |
| Seed-chain 当前密钥 | `(*SeedChain).DeriveCurrentKeyPair` | 获取当前步的确定性密钥 |
| Seed-chain 消费 | `(*SeedChain).ConsumeSeed` | 消费当前步并返回下一锚点 |

## 3. 当前支持的签名算法

### 3.1 经典签名

| 算法标识 | 说明 |
| --- | --- |
| `bls` | BLS 签名 |
| `ecdsa` | ECDSA |
| `ec_schnorr` | EC Schnorr |
| `eddsa` | EdDSA |
| `eddsa_cosmos` | Cosmos 兼容 EdDSA |
| `sm2` | 国密 SM2 |

### 3.2 后量子签名

| 算法标识 | 说明 |
| --- | --- |
| `pq_aigis_sig` | AIGIS-SIG |
| `pq_dilithium` | Dilithium |
| `pq_ml_dsa` | ML-DSA |
| `pq_slh_dsa` | SLH-DSA |

## 4. 当前支持的 KEM 算法

| 算法标识 | 说明 |
| --- | --- |
| `pq_ml_kem_512` | ML-KEM-512 |
| `pq_ml_kem_768` | ML-KEM-768 |
| `pq_ml_kem_1024` | ML-KEM-1024 |
| `pq_aigis_enc_1` | AIGIS-ENC-1 |
| `pq_aigis_enc_2` | AIGIS-ENC-2 |
| `pq_aigis_enc_3` | AIGIS-ENC-3 |
| `pq_aigis_enc_4` | AIGIS-ENC-4 |

## 5. CGO 依赖边界

| 能力 | `CGO_ENABLED=0` | `CGO_ENABLED=1` |
| --- | --- | --- |
| 经典签名 | 可用 | 可用 |
| 地址生成 | 可用 | 可用 |
| keystore | 可用 | 可用 |
| 哈希/HMAC | 可用 | 可用 |
| 经典 seed-chain | 可用 | 可用 |
| PQ 签名 | 返回明确错误 | 可用 |
| PQ KEM | 返回明确错误 | 可用 |

## 6. 推荐使用顺序

1. 先读 [external-usage-guide.md](./external-usage-guide.md)
2. 再看 [release-validation.md](./release-validation.md)
3. 最后跑 `crypto/examples/walletcrypto-seedchain-demo`
