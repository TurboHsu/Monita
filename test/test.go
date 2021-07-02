package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	fmt.Println(hex.EncodeToString([]byte("What")))
}
