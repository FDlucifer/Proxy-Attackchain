package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

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

func main() {
	testcookie := "cadata=p4TwZveLKK8xc2T4N/bQl5J/70EScESQYkeh4EZu2LAjYVee+7+4Ht/z+NKO8WWv03PY+P7/fkKRYIqheinHeUZ7HgL/gKq266Kk+Hde9NjmIyhDVAFiFYVRJtIyPRGiX4AnZupvyVC4tRdOiIr/hg==; cadataTTL=v37wzmi7MEfC9N0dOMDg2g==; cadataKey=JV9Q+2xfT4qQkRII4+9zWWbJ71RAL8sEMxUsOTM6t3GlZXdgYsP7mWa/ANGivKKxvNpleo5rGPIxK8wHx2AwRiRhDz9uGSI4oxu0Xfd5keBRUd6FY73izrofCHb/gVEel4gaHgxTWdxD6vxuEiJ8L/GVCSIzngRYG/0LOm22v/4auh2OmTLU54SZ68t2gWRtf+BZEQyQABDlvYFWZqCaHDV6IyDMflDUdgOmB77dxIo1/b1sERmZ8OzWw57zNfu5QA0wXqsE81OocmYHHTbe4haurwvLhi+jJV7wBP+IX3Px8ZJDQAvLG+OboIJ3mmrCPmJ9R1mp+mKEKkytedsQLA==; cadataIV=OjTNnqor6zXhEjzocv4XiaPaMNIwuX0sgfFsQ1/6N5IpU0I0tVbe+L95meI+CA1sVLudhfyLluBam3oN/xNgGQGnbmmJJJcxfKtx5oSgeujmFWDKAQQSQ7CGJZ8wGUKI5gmk0MQ/06I4/gZqGWDA5NeYzv7F/8Ul9zQiP5SaoION/oxuf3hWOlaIq0wWVqgbgVUYTAUPYpngb7muJrXvNZE3QOt4kbUnY0g4e3EG9sCMp+ctMrUjY+lmJGOIsZ2JENa846sfCeZHcOEp+LzhqN7XcU+8JZ2ung6trD8rmimvk/T0Ibh1ITlpm8wxiyRAKqbG0a77vquwZvE+H8kNYw==; cadataSig=aR3Slm53ss329FIbOEPcD8zr+tbWheelQzmxkRI/w3K864aoBIyqut+JoJYhyW0Gmtir1fWc4Mjua1dFhaB63OzvVZosEZDODOmfpq3KCE2n0X0mhcbLnR5CGHVY4EL/5Ro/VGqp0cocaYtMT8alcZXYlu2lM7KQBekO2VINuPqVB71iy3uZMjkk68q/KPlMOBPO7s5ezoqAMPrBvFMF9Pxhp7LrUs4BnxmH3fz+mmNMOu4vg7WRhUD+f5AOifFYHTGooUtaoYhySv+y6V9wQzL5ejuRARN4VAcnrBsEgoFOPNUKDQ8RuyCUO+Hj0R5+ZBGQlbGo9nX8N2XhkTi2tQ=="
	fmt.Println(getcadata(testcookie))
	fmt.Println("--------------------------")
	fmt.Println(getcadataTTL(testcookie))
	fmt.Println("--------------------------")
	fmt.Println(getcadataKey(testcookie))
	fmt.Println("--------------------------")
	fmt.Println(getcadataIV(testcookie))
	fmt.Println("--------------------------")
	fmt.Println(getcadataSig(testcookie))
	fmt.Println("--------------------------")
	fmt.Println("[+] cadata bytes value:\n")
	fmt.Println(getcipherbytes(getcadata(testcookie)))
	fmt.Println("----------------------------------------------------")
	locations := "https://106.55.103.31/owa/auth/logon.aspx?url=https%3a%2f%2f106.55.103.31%2fowa%2f&reason=0"
	fmt.Println(splitlocation(locations))
}
