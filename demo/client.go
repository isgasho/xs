package main

import (
	"fmt"

	hkex "blitter.com/herradurakex"
)

// Demo of a simple client that dials up to a simple test server to
// send data.
// Note this code is identical to standard tcp client code, save for
// declaring a 'hkex' rather than a 'net' Dialer Conn. The KEx and
// encrypt/decrypt is done within the type.
// Compare to 'clientp.go' in this directory to see the equivalence.
func main() {
	conn, err := hkex.Dial("tcp", "localhost:2000")
	if err != nil {
		// handle error
		fmt.Println("Err!")
	}
	fmt.Fprintf(conn, "\x01\x02\x03\x04")
	//fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	//status, err := bufio.NewReader(conn).ReadString('\n')
	//_, err = bufio.NewReader(conn).ReadString('\n')
	// ...

}
