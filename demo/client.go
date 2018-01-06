package main

import (
	"fmt"
	"net"

	hkex "blitter.com/herradurakex"
)

func main() {
	bareconn, err := net.Dial("tcp", "localhost:2000")
	if err != nil {
		// handle error
	}

	conn := hkex.NewHKExConn(&bareconn)
	fmt.Printf("conn: %v\n", conn)

	//	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	//	status, err := bufio.NewReader(conn).ReadString('\n')
	//	_, err = bufio.NewReader(conn).ReadString('\n')
	// ...
}
