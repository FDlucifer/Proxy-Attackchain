package main

import (
	"flag"
	"fmt"

	"github.com/fatih/color"
)

func Banner() {
	x := `
	----------------------
	< proxyshell is awesome! >
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

func exploit(target, email string) {

}

func main() {
	Banner()
	var target, email string
	flag.StringVar(&target, "u", "", "")
	flag.StringVar(&email, "e", "", "")
	flag.CommandLine.Usage = func() {
		fmt.Println("usage：\nexec: ./proxyshell -u <target url> -e <email>")
	}
	flag.Parse()
	if len(target) == 0 {
		fmt.Println("[+] please enter the url you want to check!!!")
		fmt.Println("[+] Author: https://github.com/FDlucifer, https://twitter.com/fdlucifer11")
	} else {
		exploit(target, email)
	}
}
