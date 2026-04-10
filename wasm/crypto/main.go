//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	fmt.Println("Go Wasm Running....")
	js.Global().Set("TestPrettyJSON", jsonWrapper())
	js.Global().Set("CanonicalizeJSON", canonicalizeJSONWrapper())
	js.Global().Set("CanonicalizeJSONExcluding", canonicalizeJSONExcludingWrapper())
	js.Global().Set("KeygenAPI", keygenAPIWrapper())
	js.Global().Set("KeygenWithSeedAPI", keygenWithSeedAPIWrapper())
	js.Global().Set("KeygenExtendAPI", keygenExtendAPIWrapper())
	js.Global().Set("SignAPI", signAPIWrapper())
	js.Global().Set("VerifyAPI", verifyAPIWrapper())
	js.Global().Set("VerifyKeyGenAPI", verifyKeyGenWrapper())
	js.Global().Set("Keccak256Hex", keccak256HexWrapper())
	js.Global().Set("PersonalSignHashHex", personalSignHashHexWrapper())
	js.Global().Set("RecoverAddressFromPersonalSignHex", recoverAddressFromPersonalSignHexWrapper())
	js.Global().Set("VerifyPersonalSignAddressHex", verifyPersonalSignAddressHexWrapper())
	js.Global().Set("Bytes32Hex", bytes32HexWrapper())
	<-make(chan bool)
}
