package walletcrypto

type KeyPair struct {
	Algorithm  string
	PrivateKey []byte
	PublicKey  []byte
}

type AddressFormat string

const (
	AddressFormatBase58Check AddressFormat = "base58check"
	AddressFormatHash160Hex  AddressFormat = "hash160_hex"
	// Deprecated: AddressFormatEthereumHex only derives a Keccak-last20 style
	// hex address from the provided public-key bytes. It is not a full EVM
	// compatibility surface and should not be used as a substitute for
	// personal_sign, address recovery, or full Ethereum account semantics.
	// Prefer github.com/19231224lhr/CryptoArea/crypto/evm for EVM-facing flows.
	AddressFormatEthereumHex AddressFormat = "ethereum_hex"
)

type AddressOptions struct {
	Format  AddressFormat
	Version byte
}

const (
	AlgBLS         = "bls"
	// AlgECDSA currently maps to the library's secp256k1 implementation.
	// It is a generic signing entry, not an EVM personal_sign alias.
	AlgECDSA       = "ecdsa"
	AlgECSchnorr   = "ec_schnorr"
	AlgEdDSA       = "eddsa"
	AlgEdDSACosmos = "eddsa_cosmos"
	AlgSM2         = "sm2"

	AlgPQAigisSig  = "pq_aigis_sig"
	AlgPQDilithium = "pq_dilithium"
	AlgPQMLDSA     = "pq_ml_dsa"
	AlgPQSLHDSA    = "pq_slh_dsa"

	AlgPQMLKEM512  = "pq_ml_kem_512"
	AlgPQMLKEM768  = "pq_ml_kem_768"
	AlgPQMLKEM1024 = "pq_ml_kem_1024"
	AlgPQAigisEnc1 = "pq_aigis_enc_1"
	AlgPQAigisEnc2 = "pq_aigis_enc_2"
	AlgPQAigisEnc3 = "pq_aigis_enc_3"
	AlgPQAigisEnc4 = "pq_aigis_enc_4"
)
