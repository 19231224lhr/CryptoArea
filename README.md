# crypto-suites

`crypto-suites` 是一个面向钱包场景的密码能力库，整合了经典密码和后量子密码能力。

目标是给上层钱包/账户系统提供统一可调用的接口，覆盖：

- 私钥/公钥生成
- 签名与验签
- 地址生成
- 后量子 KEM（密钥封装/解封装）
- keystore（私钥加密存储）
- 常用哈希/HMAC/随机数工具

## 项目结构

- `crypto/`
  - 经典密码能力（签名、哈希等）
  - 对外推荐入口：`crypto/walletcrypto`
- `pqcgo/`
  - 后量子能力（签名 + KEM）的 Go 封装
  - 通过 cgo 调用 PQMagic C 库
- `wasm/`
  - wasm 相关封装与测试代码

## 推荐使用入口

钱包项目请优先通过 `crypto/walletcrypto` 使用，不建议业务层直接耦合底层多个模块。

导入路径：

```go
import "blockchain-crypto/walletcrypto"
```

## 支持算法

经典签名算法：

- `bls`
- `ecdsa`
- `ec_schnorr`
- `eddsa`
- `eddsa_cosmos`
- `sm2`

后量子签名算法：

- `pq_aigis_sig`
- `pq_dilithium`
- `pq_ml_dsa`
- `pq_slh_dsa`

### 后量子签名算法解释（简版）

- `pq_ml_dsa`
  - 对应 NIST 标准化后的 ML-DSA（FIPS 204）路线
  - 工程上通常作为默认优先选项，兼顾成熟度与通用性
- `pq_dilithium`
  - ML-DSA 的前身体系（CRYSTALS-Dilithium 路线）
  - 适合已有 Dilithium 兼容需求的场景
- `pq_aigis_sig`
  - 格基签名路线的另一套实现
  - 适合你明确需要该算法族兼容性的场景
- `pq_slh_dsa`
  - 基于哈希的签名路线（SLH-DSA / SPHINCS+）
  - 优点是安全假设不同于格基；代价通常是签名体积更大、性能开销更高

钱包工程建议：

1. 默认主签名可优先考虑 `pq_ml_dsa`
2. 若要做“异构抗风险”，可评估增加 `pq_slh_dsa` 作为备用签名族
3. 如果你有历史兼容要求，再选择 `pq_dilithium` 或 `pq_aigis_sig`

后量子 KEM 算法：

- `pq_ml_kem_512`
- `pq_ml_kem_768`
- `pq_ml_kem_1024`
- `pq_aigis_enc_1`
- `pq_aigis_enc_2`
- `pq_aigis_enc_3`
- `pq_aigis_enc_4`

## 启动与验证（Windows + PowerShell）

1. 克隆仓库：

```powershell
git clone https://github.com/19231224lhr/CryptoArea.git
cd CryptoArea
```

2. 先验证无 cgo 路径（基础可编译性）：

```powershell
cd crypto
$env:CGO_ENABLED="0"
go test ./walletcrypto/...
```

3. 验证有 cgo 路径（后量子能力）：

```powershell
$env:CGO_ENABLED="1"
go test ./walletcrypto/...
```

4. 如需验证底层 `pqcgo`：

```powershell
cd ../pqcgo
$env:CGO_ENABLED="1"
go test ./...
```

## 对外核心接口（walletcrypto）

- 密钥生成
  - `GenerateKeyPair`
  - `GenerateKeyPairWithSeed`
- 签名验签
  - `SignMessage`
  - `VerifyMessage`
- KEM
  - `GenerateKEMKeyPair`
  - `EncapsulateSharedSecret`
  - `DecapsulateSharedSecret`
- 地址生成
  - `GenerateAddress`
- keystore
  - `EncryptPrivateKey`
  - `DecryptPrivateKey`
- 工具函数
  - `RandomBytes`
  - `HashData`
  - `HMACSHA256`

## 最小调用示例

```go
package main

import (
	"fmt"
	"blockchain-crypto/walletcrypto"
)

func main() {
	kp, err := walletcrypto.GenerateKeyPair(walletcrypto.AlgPQMLDSA)
	if err != nil {
		panic(err)
	}
	msg := []byte("tx-bytes")
	sig, err := walletcrypto.SignMessage(walletcrypto.AlgPQMLDSA, kp.PrivateKey, msg)
	if err != nil {
		panic(err)
	}
	ok, err := walletcrypto.VerifyMessage(walletcrypto.AlgPQMLDSA, kp.PublicKey, msg, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("verify:", ok)
}
```

## 钱包交易场景：哈希链回退签名

本仓库已经提供一个完整流程测试，文件与用例：

- `crypto/walletcrypto/tx_flow_cgo_test.go`
- `TestWalletTxFlowWithHashChainRollbackAndPQSign`

执行命令：

```powershell
cd crypto
$env:CGO_ENABLED="1"
go test -run TestWalletTxFlowWithHashChainRollbackAndPQSign ./walletcrypto/...
```

### 这句话到底是什么意思

“先生成哈希链密钥，从最末端开始逐级回退使用”的含义是：

1. 先准备一条链：`seed0 -> seed1 -> ... -> seedN`，其中 `seed(i+1)=Hash(seed(i))`
2. 第一笔交易不用 `seed0`，而是先用 `seedN`（最末端）
3. 下一笔用 `seedN-1`，再下一笔用 `seedN-2`，依次回退
4. 每次交易都用当前 seed 派生一个新的 PQ 签名密钥（一次一把）

### seed 到底是什么

- seed 是“确定性派生材料”，不是链上账户地址，也不是交易本体
- 在本仓库接口里，`GenerateKeyPairWithSeed(...)` 会用 seed 确定性生成一对签名密钥
- 同一个算法 + 同一个 seed，会得到同一对密钥
- 不同 seed 会得到不同密钥（因此可实现“一笔一钥”）
- 标准区块链验签不需要 seed；只有你采用“哈希链回退增强模式”时，才需要额外校验 seed 链关系

### 现实中怎么签名

建议把“账户身份”和“交易签名”分离：

- 账户身份/地址：用 `ECDSA` 公钥生成并保持不变
- 每笔交易签名：用当前步的哈希链 seed 生成 `ML-DSA` 密钥并签名

签名方每笔交易做：

1. 取当前索引 `i` 对应 seed（从 `N` 往 `0` 走）
2. `GenerateKeyPairWithSeed(AlgPQMLDSA, seed_i)` 生成当次 PQ 密钥
3. 用 `SignMessage(AlgPQMLDSA, sk_i, txBytes)` 签名
4. 在交易里携带：`pqPub_i`、`signature_i`、`step=i`，以及你协议里定义的哈希链证明字段
5. 本地将索引更新到 `i-1`，禁止重复使用同一个 `seed_i`

### 现实中怎么验证

验证方每笔交易做：

1. 用 `VerifyMessage(AlgPQMLDSA, pqPub_i, txBytes, signature_i)` 验签
2. 校验哈希链回退关系：
   - 若上一笔已披露 `seed_prev`，则验证 `Hash(seed_i) == seed_prev`
   - 首笔还应校验到你预先锚定的链头承诺（例如 `seedN` 或其承诺值）
3. 校验业务字段（nonce、余额、防重放规则等）

### 常见疑问：链上验签到底要不要 seed

分两种模式：

1. 标准区块链验签模式（最常见）
   - 不需要 seed
   - 只需要消息、签名、公钥（或可解析出公钥的脚本/地址）
   - 验证逻辑就是标准 `Verify(msg, sig, pubkey)`

2. 哈希链回退增强模式（本文讨论的方案）
   - 除了标准验签，还要验证哈希链连续性
   - 验证者不需要“整串 seed”，只需要本笔披露值和链上已有承诺值
   - 典型检查是 `Hash(seed_current) == seed_previous_or_anchor`

### 注意事项

- 这是“状态化签名流程”，钱包必须持久化当前索引 `i`
- 一旦索引回退状态丢失，可能出现 seed 重用风险
- 地址保持不变不代表签名公钥不变，签名公钥是每笔交易动态派生的

## 重要说明

- PQC 相关能力依赖 `cgo`。
  - `CGO_ENABLED=1`：启用真实后量子实现
  - `CGO_ENABLED=0`：可编译，但 PQC 接口会返回明确错误
- 当前 KEM 的正式可用路径是 `windows + cgo`。
- `pqcgo/pqmagic/build-windows-kem/` 是本地构建中间目录，不是运行必需内容，已加入 `.gitignore`。
