package main

import (
	"fmt"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("../assets"))
	err := http.ListenAndServe(":9090", http.StripPrefix("/", fs))
	if err != nil {
		fmt.Println("Failed to start server", err)
		return
	}
}
