//go:build cgo

package walletcrypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

type demoTransaction struct {
	FromAddress   string `json:"from_address"`
	ToAddress     string `json:"to_address"`
	Amount        int64  `json:"amount"`
	Nonce         uint64 `json:"nonce"`
	HashKeyStep   int    `json:"hash_key_step"`
	AccountPubKey string `json:"account_pub_key"`
}

func TestWalletTxFlowWithHashChainRollbackAndPQSign(t *testing.T) {
	// 1) 使用 ECDSA 生成钱包账户密钥和地址（账户身份）。
	accountKey, err := GenerateKeyPair(AlgECDSA)
	if err != nil {
		t.Fatalf("GenerateKeyPair(ecdsa) failed: %v", err)
	}
	fromAddr, err := GenerateAddress(accountKey.PublicKey, &AddressOptions{
		Format:  AddressFormatBase58Check,
		Version: 0x00,
	})
	if err != nil {
		t.Fatalf("GenerateAddress(from) failed: %v", err)
	}

	receiverKey, err := GenerateKeyPair(AlgECDSA)
	if err != nil {
		t.Fatalf("GenerateKeyPair(receiver ecdsa) failed: %v", err)
	}
	toAddr, err := GenerateAddress(receiverKey.PublicKey, &AddressOptions{
		Format:  AddressFormatBase58Check,
		Version: 0x00,
	})
	if err != nil {
		t.Fatalf("GenerateAddress(to) failed: %v", err)
	}

	// 2) 生成哈希链：chain[i] = H(chain[i-1])，交易签名时从末端往前用。
	const chainLen = 6
	chain := make([][]byte, chainLen)
	chain[0], err = HashData("sha256", []byte("wallet-demo-hash-chain-root"))
	if err != nil {
		t.Fatalf("hash root failed: %v", err)
	}
	for i := 1; i < chainLen; i++ {
		chain[i], err = HashData("sha256", chain[i-1])
		if err != nil {
			t.Fatalf("hash chain step %d failed: %v", i, err)
		}
	}

	// 3) 每次交易使用一个新 seed 派生 PQ 签名密钥（ML-DSA），从末端向前回退使用。
	seenPubKeys := map[string]struct{}{}
	var previousRevealedSeed []byte

	for i := chainLen - 1; i >= 0; i-- {
		seed := chain[i]
		pqKey, err := GenerateKeyPairWithSeed(AlgPQMLDSA, seed)
		if err != nil {
			t.Fatalf("GenerateKeyPairWithSeed(pq_ml_dsa) failed at step %d: %v", i, err)
		}

		pkHex := hex.EncodeToString(pqKey.PublicKey)
		if _, exists := seenPubKeys[pkHex]; exists {
			t.Fatalf("unexpected duplicated PQ public key at step %d", i)
		}
		seenPubKeys[pkHex] = struct{}{}

		tx := demoTransaction{
			FromAddress:   fromAddr,
			ToAddress:     toAddr,
			Amount:        int64(100 + (chainLen - i)),
			Nonce:         uint64(chainLen - 1 - i),
			HashKeyStep:   i,
			AccountPubKey: hex.EncodeToString(accountKey.PublicKey),
		}
		txBytes, err := json.Marshal(tx)
		if err != nil {
			t.Fatalf("marshal tx failed at step %d: %v", i, err)
		}

		signature, err := SignMessage(AlgPQMLDSA, pqKey.PrivateKey, txBytes)
		if err != nil {
			t.Fatalf("SignMessage(pq_ml_dsa) failed at step %d: %v", i, err)
		}
		ok, err := VerifyMessage(AlgPQMLDSA, pqKey.PublicKey, txBytes, signature)
		if err != nil {
			t.Fatalf("VerifyMessage(pq_ml_dsa) failed at step %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("VerifyMessage returned false at step %d", i)
		}

		// 回退使用校验：如果上一笔交易已披露 seed_next，则应满足 H(seed_current) = seed_next。
		if previousRevealedSeed != nil {
			nextFromCurrent, err := HashData("sha256", seed)
			if err != nil {
				t.Fatalf("hash rollback check failed at step %d: %v", i, err)
			}
			if !bytes.Equal(nextFromCurrent, previousRevealedSeed) {
				t.Fatalf("hash-chain rollback mismatch at step %d", i)
			}
		}
		previousRevealedSeed = seed
	}
}
