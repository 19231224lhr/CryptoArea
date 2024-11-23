package main

import (
	"blockchain-crypto/signature"
	"encoding/json"
	"fmt"
	"syscall/js"
)

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

func keygenAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		sk, pk := signature.KeygenAPI(scheme)
		return map[string]interface{}{
			"sk": sk,
			"pk": pk,
		}
	})
}

func keygenWithSeedAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		seed := []byte(args[1].String())
		sk, pk := signature.KeygenWithSeedAPI(scheme, seed)
		return map[string]interface{}{
			"sk": sk,
			"pk": pk,
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
		return map[string]interface{}{
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
		sk := []byte(args[1].String())
		mes := []byte(args[2].String())
		sig := signature.SignAPI(scheme, sk, mes)
		return sig
	})
}

func verifyAPIWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 4 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		pk := []byte(args[1].String())
		mes := []byte(args[2].String())
		sig := []byte(args[3].String())
		result := signature.VerifyApi(scheme, pk, mes, sig)
		return result
	})
}

func verifyKeyGenWrapper() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 4 {
			return "Invalid number of arguments passed"
		}
		scheme := args[0].String()
		forwardPK := []byte(args[1].String())
		backwardSK := []byte(args[2].String())
		backwardPK := []byte(args[3].String())
		result := signature.VerifyKeyGen(scheme, forwardPK, backwardSK, backwardPK)
		return result
	})
}
