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
	"strings"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
)

var config clientConfig

func main() {
	//Read Config.
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal("[E] Read config failed:", err)
	}
	defer configFile.Close()
	byteValue, _ := ioutil.ReadAll(configFile)

	json.Unmarshal([]byte(byteValue), &config)

	//Client Hello
	message := "Client Hello!"
	encrypted, err := AesEncrypt([]byte(message), []byte(config.ServerKey))
	if err != nil {
		log.Fatal("[E] Encrypt data error:", err)
		return
	}
	encrypted64 := base64.StdEncoding.EncodeToString(encrypted)

	handshake, _ := http.NewRequest("POST", config.ServerAddr, strings.NewReader(encrypted64))
	handshakeResp, err := http.DefaultClient.Do(handshake)
	if err != nil {
		log.Fatal("[E] Post data error:", err)
	} else {
		handshakeRespDataCrypted64, _ := ioutil.ReadAll(handshakeResp.Body)
		handshakeRespDataCrypted, _ := base64.StdEncoding.DecodeString(string(handshakeRespDataCrypted64))
		handshakeRespData, _ := AesDecrypt([]byte(string(handshakeRespDataCrypted)), []byte(config.ServerKey))
		if string(handshakeRespData) == "Server Hello!" {
			log.Println("[I] Handshake success to", config.ServerAddr)
		} else {
			log.Fatal("[E] Server handshake failed: Response not match:", string(handshakeRespData))
		}
	}

	//Examples for machine info.
	fmt.Println(encrypted64)
	fmt.Println(getCpuPercent())
	fmt.Println(getMemPercent())
	fmt.Println(getDiskPercent())
	log.Println("[I] Start post loop by:", config.PostInterval, "*Second")
	for true {
		time.Sleep(config.PostInterval * time.Second)
		sendData()
	}
}

// Datasets
type clientConfig struct {
	ServerAddr   string        `json:"server_addr"`
	ServerKey    string        `json:"server_key"`
	ClientName   string        `json:"client_name"`
	PostInterval time.Duration `json:"post_interval"`
}

// Funcs
func sendData() {
	fmt.Println("test")
	//Gotta to send data here.
}

func getCpuPercent() float64 {
	percent, _ := cpu.Percent(time.Second, false)
	return percent[0]
}

func getMemPercent() float64 {
	memInfo, _ := mem.VirtualMemory()
	return memInfo.UsedPercent
}

func getDiskPercent() float64 {
	parts, _ := disk.Partitions(true)
	diskInfo, _ := disk.Usage(parts[0].Mountpoint)
	return diskInfo.UsedPercent
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
