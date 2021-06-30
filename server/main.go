package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var config serverConfig

func main() {
	//Read Config
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal("[E] Read config failed:", err)
	}
	defer configFile.Close()
	byteValue, _ := ioutil.ReadAll(configFile)
	json.Unmarshal([]byte(byteValue), &config)

	log.Println("[I] Server started at:", config.ListenAddr, config.APIServePath)
	//Start Web Listener
	http.HandleFunc(config.APIServePath, APIHandler)
	http.ListenAndServe(config.ListenAddr, nil)
}

//Datasets
type serverConfig struct {
	ServerKey    string `json:"server_key"`
	ListenAddr   string `json:"listen_addr"`
	APIServePath string `json:"api_serve_path"`
}

// Funcs

func APIHandler(w http.ResponseWriter, r *http.Request) {
	dataCrypted, _ := ioutil.ReadAll(r.Body)
	data, _ := AesDecrypt([]byte(dataCrypted), []byte(config.ServerKey))
	if string(data) == "Client Hello!" { //Deal with ClientHello
		msg, _ := AesEncrypt([]byte("Server Hello!"), []byte(config.ServerKey))
		fmt.Fprintf(w, string(msg))
		log.Println("[I] Served handshake from:", r.RemoteAddr)
	} else if strings.Contains(string(data), "CLIDATA") { //Deal with Client data.
		msg, _ := AesEncrypt([]byte("RECEIVED"), []byte(config.ServerKey))
		fmt.Fprintf(w, string(msg))
		processedData := strings.Split(string(data), "|")
		fmt.Println(processedData)

	}

	//Gotta to write some functions.
	/*
		一些设想：
		准备使用litesql之类的数据库，
		接收到数据之后存入数据表，用客户端发送的唯一名称来命名，然后记录下他什么时间是什么数值。
		用json之类的存储也行，这个再说，或者说这个过程由客户端来完成也行，数据存储在客户端那边，需要的时候再拉取。

		网页方面想要实现监视的样子，然后还有实时数据显示，图表啊啥的（美丽的设想
	*/
}

func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}
