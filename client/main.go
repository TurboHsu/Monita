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
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
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

	if sendData("Client Hello!") != "Server Hello!" {
		log.Fatal("[E] Handshake failed.")
	} else {
		log.Println("[I] Started Monita client. Server:", config.ServerAddr)
	}

	log.Println("[I] Start post loop by:", int(config.PostInterval), "ms")
	var data string
	for true {
		time.Sleep(config.PostInterval * time.Millisecond)
		data = fmt.Sprintf("CLIDATA|%v|%v|%v|%v", time.Now().Unix(), getCPUPercent(), getMemPercent(), getDiskPercent())
		if sendData(data) != "RECEIVED" {
			log.Println("[E] Response missing.")
		}
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
func sendData(message string) string {
	var response string
	encrypted, err := AesEncrypt([]byte(message), []byte(config.ServerKey))
	if err != nil {
		log.Fatal("[E] Encrypt data error:", err)
	}
	sendMsg, _ := http.NewRequest("POST", config.ServerAddr, strings.NewReader(string(encrypted)))
	sendMsgResp, err := http.DefaultClient.Do(sendMsg)
	if err != nil {
		log.Println("[E] Post data error:", err)
	} else {
		msgRecCrypted, _ := ioutil.ReadAll(sendMsgResp.Body)
		msgRec, _ := AesDecrypt([]byte(string(msgRecCrypted)), []byte(config.ServerKey))
		response = string(msgRec)
	}
	return response
}

func getCPUPercent() float64 {
	percent, _ := cpu.Percent(time.Millisecond*100, false) //Get 100ms of cpu usage, which is a bit more accurate.
	ret, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", percent[0]), 64)
	return ret
}

func getMemPercent() float64 {
	memInfo, _ := mem.VirtualMemory()
	return memInfo.UsedPercent
}

func getDiskPercent() float64 {
	parts, _ := disk.Partitions(true)
	diskInfo, _ := disk.Usage(parts[0].Mountpoint)
	ret, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", diskInfo.UsedPercent), 64)
	return ret
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
