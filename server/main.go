package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
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

	//Start Web Listener
	http.HandleFunc("/api", APIHandler)
	http.ListenAndServe(":8000", nil)
}

//Datasets
type serverConfig struct {
	ServerKey string `json:"server_key"`
}

// Funcs

func APIHandler(w http.ResponseWriter, r *http.Request) {
	dataRaw, _ := ioutil.ReadAll(r.Body)
	dataCrypted, _ := base64.StdEncoding.DecodeString(string(dataRaw))
	data, _ := AesDecrypt([]byte(dataCrypted), []byte(config.ServerKey))
	fmt.Printf(string(data))
	if string(data) == "Client Hello!" { //Deal with ClientHello
		msg, _ := AesEncrypt([]byte("Server Hello!"), []byte(config.ServerKey))
		fmt.Fprintf(w, string(base64.StdEncoding.EncodeToString(msg)))
		log.Println("[I] Served handshake from:", r.RemoteAddr)
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

//@brief:填充明文
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//@brief:去除填充数据
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//@brief:AES加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//@brief:AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}
