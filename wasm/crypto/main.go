//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	fmt.Println("Go Wasm Running....")
	js.Global().Set("TestPrettyJSON", jsonWrapper())
	js.Global().Set("KeygenAPI", keygenAPIWrapper())
	js.Global().Set("KeygenWithSeedAPI", keygenWithSeedAPIWrapper())
	js.Global().Set("KeygenExtendAPI", keygenExtendAPIWrapper())
	js.Global().Set("SignAPI", signAPIWrapper())
	js.Global().Set("VerifyAPI", verifyAPIWrapper())
	js.Global().Set("VerifyKeyGenAPI", verifyKeyGenWrapper())
	<-make(chan bool)
}
