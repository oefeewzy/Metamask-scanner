package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/net/proxy"
)

var networks = map[string]string{
	"ethereum":  "https://api.blockchair.com/ethereum/dashboards/address/",
	"bsc":       "https://api.blockchair.com/binance-smart-chain/dashboards/address/",
	"polygon":   "https://api.blockchair.com/polygon/dashboards/address/",
	"avalanche": "https://api.snowtrace.io/api?module=account&action=balance&address=",
	"fantom":    "https://api.ftmscan.com/api?module=account&action=balance&address=",
	"arbitrum":  "https://api.arbiscan.io/api?module=account&action=balance&address=",
	"optimism":  "https://api-optimistic.etherscan.io/api?module=account&action=balance&address=",
	"base":      "https://api.basescan.org/api?module=account&action=balance&address=",
	"gnosis":    "https://blockscout.com/xdai/mainnet/api?module=account&action=balance&address=",
}

func loadProxies() []string {
	file, err := os.Open("proxies.txt")
	if err != nil {
		return nil
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxies = append(proxies, scanner.Text())
	}
	return proxies
}

func randomProxyClient(proxies []string) *http.Client {
	if len(proxies) == 0 {
		return http.DefaultClient
	}
	raw := proxies[rand.Intn(len(proxies))]
	proxyURL, err := url.Parse(raw)
	if err != nil {
		return http.DefaultClient
	}

	if proxyURL.Scheme == "socks5" {
		dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, nil, proxy.Direct)
		if err != nil {
			return http.DefaultClient
		}
		dialContext := func(network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
		return &http.Client{
			Transport: &http.Transport{Dial: dialContext},
			Timeout:   15 * time.Second,
		}
	}

	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}
}

func checkBalance(client *http.Client, addr string) bool {
	for _, base := range networks {
		fullURL := base + addr
		resp, err := client.Get(fullURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(base, "blockchair") {
			var res map[string]interface{}
			if json.Unmarshal(body, &res) == nil {
				if data, ok := res["data"].(map[string]interface{}); ok {
					if obj, ok := data[strings.ToLower(addr)].(map[string]interface{}); ok {
						info := obj["address"].(map[string]interface{})
						bal, _ := strconv.ParseInt(info["balance"].(string), 10, 64)
						tx := int(info["transaction_count"].(float64))
						if bal > 0 || tx > 0 {
							return true
						}
					}
				}
			}
		} else {
			var res map[string]interface{}
			if json.Unmarshal(body, &res) == nil {
				if v, ok := res["result"].(string); ok {
					if val, _ := strconv.ParseInt(v, 10, 64); val > 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

func deriveETHAddress(seed []byte, index int) (common.Address, error) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return common.Address{}, err
	}
	purpose, _ := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	coinType, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coinType.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(0)
	addressIndex, _ := change.NewChildKey(uint32(index))
	privateKey, err := crypto.ToECDSA(addressIndex.Key)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(privateKey.PublicKey), nil
}

func main() {
	find := flag.Int("find", 10, "Сколько активных кошельков найти")
	derivationRange := flag.String("range", "0-0", "Диапазон индексов: 0-10")
	flag.Parse()

	start, end := 0, 0
	parts := strings.Split(*derivationRange, "-")
	if len(parts) == 2 {
		start, _ = strconv.Atoi(parts[0])
		end, _ = strconv.Atoi(parts[1])
	}

	proxies := loadProxies()
	found := [][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	fmt.Println("Поиск активных кошельков...")

	for len(found) < *find {
		entropy, _ := bip39.NewEntropy(128)
		mnemonic, _ := bip39.NewMnemonic(entropy)
		seed := bip39.NewSeed(mnemonic, "")

		for i := start; i <= end; i++ {
			addr, err := deriveETHAddress(seed, i)
			if err != nil {
				continue
			}
			wg.Add(1)
			go func(mnemonic string, addr common.Address) {
				defer wg.Done()
				client := randomProxyClient(proxies)
				if checkBalance(client, addr.Hex()) {
					mu.Lock()
					found = append(found, []string{mnemonic, addr.Hex()})
					fmt.Printf("[FOUND] %s\n", addr.Hex())
					mu.Unlock()
				}
			}(mnemonic, addr)

			if len(found) >= *find {
				break
			}
		}
		wg.Wait()
	}

	f, _ := os.Create("found.csv")
	writer := csv.NewWriter(f)
	writer.Write([]string{"Mnemonic", "Address"})
	writer.WriteAll(found)
	writer.Flush()
	fmt.Println("Готово! Найдено:", len(found))
}
