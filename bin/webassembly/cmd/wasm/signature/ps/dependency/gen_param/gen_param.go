package main

import (
	pbc_go "blockchain-crypto/signature/lib_sig/pbc_go"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	// The authority generates system parameters
	//params, _ := pbc_go.GenerateG(9563, 160, 171, 500)
	params := pbc_go.GenerateA(160, 512)
	print(params.String())
	_, err := os.Create("curveparams")
	if err != nil {
		log.Printf("文件创建失败")
		return
	}
	paramsbyte := []byte(params.String())
	if err := ioutil.WriteFile("curveparams", paramsbyte, 0666); err != nil {
		log.Printf("写入文件失败")
		return
	}
	log.Printf("写入文件成功")
}
