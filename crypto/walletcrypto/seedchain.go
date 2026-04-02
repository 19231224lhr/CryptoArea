package walletcrypto

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidSeedChainLength = errors.New("invalid seed chain length")
	ErrInvalidSeedChainStep   = errors.New("invalid seed chain step")
	ErrSeedChainExhausted     = errors.New("seed chain exhausted")
)

// SeedChain manages a deterministic hash chain used to derive a different key
// pair per step. The chain is built as:
//
//	seed[0] = seed0
//	seed[i] = SHA256(seed[i-1])
//
// Spending-style flows typically start from the tail of the chain
// (CurrentStep = ChainLength) and roll backwards to 1.
type SeedChain struct {
	Algorithm   string
	Seed0       []byte
	ChainLength int
	CurrentStep int
	Seeds       [][]byte
}

// NewSeedChain creates a new deterministic seed chain using a random 32-byte
// root seed.
func NewSeedChain(algorithm string, chainLength int) (*SeedChain, error) {
	seed0, err := RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return NewSeedChainFromSeed(algorithm, seed0, chainLength)
}

// NewSeedChainFromSeed creates a new deterministic seed chain from a caller
// supplied root seed.
func NewSeedChainFromSeed(algorithm string, seed0 []byte, chainLength int) (*SeedChain, error) {
	return buildSeedChain(algorithm, seed0, chainLength, chainLength)
}

// RecoverSeedChain reconstructs a seed chain from the root seed and the
// current step pointer.
func RecoverSeedChain(algorithm string, seed0 []byte, chainLength int, currentStep int) (*SeedChain, error) {
	return buildSeedChain(algorithm, seed0, chainLength, currentStep)
}

func buildSeedChain(algorithm string, seed0 []byte, chainLength int, currentStep int) (*SeedChain, error) {
	if _, err := resolveAlgorithm(algorithm); err != nil {
		return nil, err
	}
	if len(seed0) == 0 {
		return nil, fmt.Errorf("seed0 must not be empty")
	}
	if chainLength < 1 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidSeedChainLength, chainLength)
	}
	if currentStep < 0 || currentStep > chainLength {
		return nil, fmt.Errorf("%w: %d", ErrInvalidSeedChainStep, currentStep)
	}

	seeds := make([][]byte, chainLength+1)
	seeds[0] = cloneBytes(seed0)
	for i := 1; i <= chainLength; i++ {
		next, err := HashData("sha256", seeds[i-1])
		if err != nil {
			return nil, err
		}
		seeds[i] = next
	}

	return &SeedChain{
		Algorithm:   algorithm,
		Seed0:       cloneBytes(seed0),
		ChainLength: chainLength,
		CurrentStep: currentStep,
		Seeds:       seeds,
	}, nil
}

// RemainingSteps returns how many spendable steps remain.
func (sc *SeedChain) RemainingSteps() int {
	if sc == nil || sc.CurrentStep < 0 {
		return 0
	}
	return sc.CurrentStep
}

// SeedAtStep returns a copy of the seed at a specific step.
func (sc *SeedChain) SeedAtStep(step int) ([]byte, error) {
	if sc == nil {
		return nil, fmt.Errorf("seed chain is nil")
	}
	if step < 1 || step > sc.ChainLength {
		return nil, fmt.Errorf("%w: %d", ErrInvalidSeedChainStep, step)
	}
	return cloneBytes(sc.Seeds[step]), nil
}

// CurrentSeed returns a copy of the seed at the current step.
func (sc *SeedChain) CurrentSeed() ([]byte, error) {
	if sc == nil {
		return nil, fmt.Errorf("seed chain is nil")
	}
	if sc.CurrentStep < 1 {
		return nil, ErrSeedChainExhausted
	}
	return sc.SeedAtStep(sc.CurrentStep)
}

// AnchorAtStep returns SHA256(seed[step]), which is the typical anchor value
// used to lock funds or state to a future reveal.
func (sc *SeedChain) AnchorAtStep(step int) ([]byte, error) {
	seed, err := sc.SeedAtStep(step)
	if err != nil {
		return nil, err
	}
	return HashData("sha256", seed)
}

// CurrentAnchor returns the anchor for the current step.
func (sc *SeedChain) CurrentAnchor() ([]byte, error) {
	if sc == nil {
		return nil, fmt.Errorf("seed chain is nil")
	}
	if sc.CurrentStep < 1 {
		return nil, ErrSeedChainExhausted
	}
	return sc.AnchorAtStep(sc.CurrentStep)
}

// DeriveKeyPairAtStep deterministically derives a key pair from a specific
// step's seed.
func (sc *SeedChain) DeriveKeyPairAtStep(step int) (*KeyPair, error) {
	seed, err := sc.SeedAtStep(step)
	if err != nil {
		return nil, err
	}
	return GenerateKeyPairWithSeed(sc.Algorithm, seed)
}

// DeriveCurrentKeyPair derives a key pair from the current step.
func (sc *SeedChain) DeriveCurrentKeyPair() (*KeyPair, error) {
	if sc == nil {
		return nil, fmt.Errorf("seed chain is nil")
	}
	if sc.CurrentStep < 1 {
		return nil, ErrSeedChainExhausted
	}
	return sc.DeriveKeyPairAtStep(sc.CurrentStep)
}

// ConsumeSeed consumes the current step, derives the corresponding key pair,
// returns the revealed seed and the anchor for the next step, and then moves
// CurrentStep backwards by one.
func (sc *SeedChain) ConsumeSeed() (seed []byte, keyPair *KeyPair, step int, nextAnchor []byte, err error) {
	if sc == nil {
		return nil, nil, 0, nil, fmt.Errorf("seed chain is nil")
	}
	if sc.CurrentStep < 1 {
		return nil, nil, 0, nil, ErrSeedChainExhausted
	}

	step = sc.CurrentStep
	seed, err = sc.SeedAtStep(step)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	keyPair, err = GenerateKeyPairWithSeed(sc.Algorithm, seed)
	if err != nil {
		return nil, nil, 0, nil, err
	}

	nextStep := step - 1
	if nextStep >= 1 {
		nextAnchor, err = sc.AnchorAtStep(nextStep)
		if err != nil {
			return nil, nil, 0, nil, err
		}
	}

	sc.CurrentStep = nextStep
	return seed, keyPair, step, nextAnchor, nil
}

func cloneBytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}
