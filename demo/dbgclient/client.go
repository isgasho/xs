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
	var server string

	flag.StringVar(&server, "s", "localhost:2000", "server hostname/address[:port]")
	flag.Parse()

	conn, err := hkex.Dial("tcp", server)
	if err != nil {
		fmt.Println("Err!")
		panic(err)
	}
	_, err = io.Copy(conn, os.Stdin)
	if err != nil && err.Error() != "EOF" {
		fmt.Println(err)
	}
}
