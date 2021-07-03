package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var config serverConfig
var dataRec [][]string

func main() {
	//Read Config
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal("[E] Read config failed:", err)
	}
	defer configFile.Close()
	byteValue, _ := ioutil.ReadAll(configFile)
	json.Unmarshal([]byte(byteValue), &config)

	//Calculate MD5 of ServerKey for AES256 Encryption.
	config.ServerKey = md5Calc(config.ServerKey)
	log.Println("[I] CLIAPI Server started at:", config.ListenAddr, config.CLIAPIServePath)
	//Start Web Listener
	http.HandleFunc(config.CLIAPIServePath, CLIAPIHandler)
	http.HandleFunc(config.WEBAPIServePath, WEBAPIHandler)
	http.ListenAndServe(config.ListenAddr, nil)
}

//Datasets
type serverConfig struct {
	ServerKey       string `json:"server_key"`
	ListenAddr      string `json:"listen_addr"`
	CLIAPIServePath string `json:"cli_api_serve_path"`
	WEBAPIServePath string `json:"web_api_serve_path"`
	WEBAPIAccessKey string `json:"web_api_key"`
}

type dataRealtimeOutput struct {
	ServerStatus []dataRealtimeOutputServers `json:"status"`
}

type dataRealtimeOutputServers struct {
	ServerName     string `json:"name"`
	ServerUNIXTime string `json:"unix_time"`
	ServerCPURate  string `json:"cpu_rate"`
	ServerMemRate  string `json:"mem_rate"`
	ServerDiskRate string `json:"disk_rate"`
}

type dataSavedOutput struct {
}

// Funcs

//WebReq: type datanow/datasaved

//WEBAPIHandler deals with web requests.
func WEBAPIHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Println("[E] Cannot parse form from:", r.Host, err)
	}
	if r.FormValue("key") == config.WEBAPIAccessKey {
		if r.FormValue("type") == "datanow" {
			var data dataRealtimeOutput
			for i := 0; i < len(dataRec); i++ {
				data.ServerStatus = append(data.ServerStatus, dataRealtimeOutputServers{ServerName: dataRec[i][0], ServerUNIXTime: dataRec[i][1], ServerCPURate: dataRec[i][2], ServerMemRate: dataRec[i][3], ServerDiskRate: dataRec[i][4]})
			}
			dataJSON, err := json.Marshal(data)
			if err != nil {
				log.Println("[E] JSON Marshal failed while processing response data:", err)
			}
			fmt.Fprintf(w, string(dataJSON))
		} else if r.FormValue("type") == "datasaved" {
			//Read from file.
		}
	} else {
		fmt.Fprintf(w, "Forbidden.")
	}
}

//CLIAPIHandler deals with Client Requests
func CLIAPIHandler(w http.ResponseWriter, r *http.Request) {
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
		//[0] CLIDATA [1] CliName [2]UNIXTime [3]CPURate [4]MemRate [5]DiskRate

		//Write into dataRec
		var existStat bool //Define a bool to judge whether this client exists.

		for i := 0; i < len(dataRec); i++ {
			if dataRec[i][0] == processedData[1] {
				dataRec[i][1] = processedData[2]
				dataRec[i][2] = processedData[3]
				dataRec[i][3] = processedData[4]
				dataRec[i][4] = processedData[5] //Write into dataRec.
				existStat = true                 //Set bool to ture.
			}
		}
		if existStat != true { //If bool isnt ture, then this data isn't exist, or dataRec is empty.
			dataRec = append(dataRec, []string{processedData[1], processedData[2], processedData[3], processedData[4], processedData[5]})
		}
		//dataRec [[0] CliName [1]UNIXTime [2]CPURate [3]MemRate [4]DiskRate],[]...

		//Write into file
		filePath := fmt.Sprintf("./data/%v", processedData[1])
		_, err := os.Stat(filePath)
		if err != nil {
			f, err := os.Create(filePath)
			defer f.Close()
			if err != nil {
				log.Println("[E] File create error:", err)
			}
		}

		recFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Println("[E] File open err:", err)
		}
		defer recFile.Close()
		if _, err = recFile.WriteString(fmt.Sprintf("%v|%v|%v|%v\n", processedData[2], processedData[3], processedData[4], processedData[5])); err != nil {
			log.Println("[E] File write err:", err)
		}

	}

}

//PKCS5Padding for AES
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//PKCS5UnPadding for AES
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//AesEncrypt encrypts []byte with key.
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

//AesDecrypt decrypts []byte with key.
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

func md5Calc(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
