package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
)

func AESGCMEncrypt(key []byte, nonce []byte, plaintext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid gcm nonce length: got %d want %d", len(nonce), gcm.NonceSize())
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func AESGCMDecrypt(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid gcm nonce length: got %d want %d", len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func AESOFBEncrypt(key []byte, iv []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("invalid ofb iv length: got %d want %d", len(iv), block.BlockSize())
	}
	stream := cipher.NewOFB(block, iv)
	out := make([]byte, len(plaintext))
	stream.XORKeyStream(out, plaintext)
	return out, nil
}

func AESOFBDecrypt(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	return AESOFBEncrypt(key, iv, ciphertext)
}

func AESOFBEncryptFile(key []byte, iv []byte, inPath string, outPath string) error {
	return transformOFBFile(key, iv, inPath, outPath)
}

func AESOFBDecryptFile(key []byte, iv []byte, inPath string, outPath string) error {
	return transformOFBFile(key, iv, inPath, outPath)
}

func transformOFBFile(key []byte, iv []byte, inPath string, outPath string) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	if len(iv) != block.BlockSize() {
		return fmt.Errorf("invalid ofb iv length: got %d want %d", len(iv), block.BlockSize())
	}

	input, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer output.Close()

	stream := cipher.NewOFB(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: output}
	_, err = io.Copy(writer, input)
	return err
}
