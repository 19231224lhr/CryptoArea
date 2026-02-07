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
	AddressFormatEthereumHex AddressFormat = "ethereum_hex"
)

type AddressOptions struct {
	Format  AddressFormat
	Version byte
}

const (
	AlgBLS         = "bls"
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
