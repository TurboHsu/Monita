package main

import (
	"fmt"
	"os"
)

func main() {
	_, err := os.Stat("a") //os.Stat获取文件信息
	if err != nil {
		fmt.Println("2")
	}
	fmt.Println("3")
}
