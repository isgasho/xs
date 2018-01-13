package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	hkex "blitter.com/herradurakex"
)

// Demo of a simple client that dials up to a simple test server to
// send data.
// Note this code is identical to standard tcp client code, save for
// declaring a 'hkex' rather than a 'net' Dialer Conn. The KEx and
// encrypt/decrypt is done within the type.
// Compare to 'clientp.go' in this directory to see the equivalence.
func main() {
	var cAlg string
	var hAlg string
	var server string

	flag.StringVar(&cAlg, "c", "C_AES_256", "cipher [\"C_AES_256\" | \"C_TWOFISH_128\" | \"C_BLOWFISH_64\"]")
	flag.StringVar(&hAlg, "h", "H_SHA256", "hmac [\"H_SHA256\"]")
	flag.StringVar(&server, "s", "localhost:2000", "server hostname/address[:port]")
	flag.Parse()

	conn, err := hkex.Dial("tcp", server, cAlg, hAlg)
	if err != nil {
		fmt.Println("Err!")
		panic(err)
	}
	_, err = io.Copy(conn, os.Stdin)
	if err != nil && err.Error() != "EOF" {
		fmt.Println(err)
	}
}
