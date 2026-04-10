//go:build js && wasm

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/19231224lhr/CryptoArea/crypto/encoding/canonical"
	"github.com/19231224lhr/CryptoArea/crypto/evm"
	"github.com/19231224lhr/CryptoArea/crypto/signature"
	"strings"
	"syscall/js"
)

func keygenAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		sk, pk := signature.KeygenAPI(scheme)
		return map[string]interface{}{
			"sk": hex.EncodeToString(sk),
			"pk": hex.EncodeToString(pk),
		}
	})
}

func keygenWithSeedAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		seedHex := args[1].String()
		println("scheme", scheme)
		println("seed", seedHex)
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		sk, pk := signature.KeygenWithSeedAPI(scheme, seed)
		return map[string]interface{}{
			"sk": hex.EncodeToString(sk),
			"pk": hex.EncodeToString(pk),
		}
	})
}

func keygenExtendAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		tValue := uint8(args[1].Int())
		sk, pk := signature.KeygenExtendAPI(scheme, tValue)
		return map[string]interface{}{ // TODO encode to hex
			"sk": sk,
			"pk": pk,
		}
	})
}

func signAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 3 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		mesHex := args[1].String()
		skHex := args[2].String()
		sk, err := hex.DecodeString(skHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		mes, err := hex.DecodeString(mesHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		sig := signature.SignAPI(scheme, sk, mes)
		fmt.Printf("scheme:%s, sk:%s, mes:%s, sig:%s\n", scheme, skHex, mesHex, hex.EncodeToString(sig))
		return hex.EncodeToString(sig)
	})
}

func verifyAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 4 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		mesHex := args[1].String()
		sigHex := args[2].String()
		pkHex := args[3].String()
		pk, err := hex.DecodeString(pkHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		mes, err := hex.DecodeString(mesHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		fmt.Printf("scheme:%s, pk:%s, mes:%s, sig:%s\n", scheme, pkHex, mesHex, sigHex)
		result := signature.VerifyAPI(scheme, pk, mes, sig)
		return result
	})
}

func verifyKeyGenWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 4 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		forwardPKHex := args[1].String()
		backwardSKHex := args[2].String()
		backwardPKHex := args[3].String()
		forwardPK, err := hex.DecodeString(forwardPKHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		backwardSK, err := hex.DecodeString(backwardSKHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		backwardPK, err := hex.DecodeString(backwardPKHex)
		if err != nil {
			fmt.Println("Error decoding hex string:", err)
			return nil
		}
		result := signature.VerifyKeyGen(scheme, forwardPK, backwardSK, backwardPK)
		return result
	})
}

func prettyJson(input string) (string, error) {
	var raw interface{}
	if err := json.Unmarshal([]byte(input), &raw); err != nil {
		return "", err
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}

func jsonWrapper() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid no of arguments passed"
		}
		inputJSON := args[0].String()
		fmt.Printf("input %s\n", inputJSON)
		pretty, err := prettyJson(inputJSON)
		if err != nil {
			fmt.Printf("unable to convert to json %s\n", err)
			return err.Error()
		}
		return pretty
	})
	return jsonFunc
}

func canonicalizeJSONWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid number of arguments passed"
		}
		raw, err := decodeJSONArg(args[0].String())
		if err != nil {
			return err.Error()
		}
		out, err := canonical.Canonicalize(raw)
		if err != nil {
			return err.Error()
		}
		return out
	})
}

func canonicalizeJSONExcludingWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "Invalid number of arguments passed"
		}
		raw, err := decodeJSONArg(args[0].String())
		if err != nil {
			return err.Error()
		}
		exclude, err := decodeStringListArg(args[1])
		if err != nil {
			return err.Error()
		}
		out, err := canonical.CanonicalizeExcluding(raw, exclude)
		if err != nil {
			return err.Error()
		}
		return out
	})
}

func keccak256HexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid number of arguments passed"
		}
		input, err := decodeHexArg(args[0].String())
		if err != nil {
			return err.Error()
		}
		return hex.EncodeToString(evm.Keccak256(input))
	})
}

func personalSignHashHexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid number of arguments passed"
		}
		message, err := decodeHexArg(args[0].String())
		if err != nil {
			return err.Error()
		}
		return hex.EncodeToString(evm.PersonalSignHash(message))
	})
}

func recoverAddressFromPersonalSignHexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "Invalid number of arguments passed"
		}
		message, err := decodeHexArg(args[0].String())
		if err != nil {
			return err.Error()
		}
		signature, err := decodeHexArg(args[1].String())
		if err != nil {
			return err.Error()
		}
		address, err := evm.RecoverAddressFromPersonalSign(message, signature)
		if err != nil {
			return err.Error()
		}
		return address
	})
}

func verifyPersonalSignAddressHexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 3 {
			return "Invalid number of arguments passed"
		}
		message, err := decodeHexArg(args[0].String())
		if err != nil {
			return err.Error()
		}
		signature, err := decodeHexArg(args[1].String())
		if err != nil {
			return err.Error()
		}
		ok, err := evm.VerifyPersonalSignAddress(message, signature, args[2].String())
		if err != nil {
			return err.Error()
		}
		return ok
	})
}

func bytes32HexWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid number of arguments passed"
		}
		input, err := decodeHexArg(args[0].String())
		if err != nil {
			return err.Error()
		}
		out, err := evm.Bytes32Hex(input)
		if err != nil {
			return err.Error()
		}
		return out
	})
}

func decodeJSONArg(input string) (interface{}, error) {
	var raw interface{}
	if err := json.Unmarshal([]byte(input), &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func decodeStringListArg(value js.Value) ([]string, error) {
	if value.Type() == js.TypeString {
		return []string{value.String()}, nil
	}
	if value.Type() != js.TypeObject {
		return nil, fmt.Errorf("exclude must be a string or array of strings")
	}
	length := value.Length()
	out := make([]string, 0, length)
	for i := 0; i < length; i++ {
		entry := value.Index(i)
		if entry.Type() != js.TypeString {
			return nil, fmt.Errorf("exclude[%d] must be a string", i)
		}
		out = append(out, entry.String())
	}
	return out, nil
}

func decodeHexArg(input string) ([]byte, error) {
	normalized := strings.TrimPrefix(strings.TrimSpace(input), "0x")
	if normalized == "" {
		return nil, fmt.Errorf("hex input must not be empty")
	}
	return hex.DecodeString(normalized)
}
