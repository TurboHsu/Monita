package main

import "fmt"

func main() {
	var data [][]string
	data = append(data, []string{"1", "2"})
	data = append(data, []string{"4", "8"})
	fmt.Println(data)
	fmt.Println(len(data))
}
