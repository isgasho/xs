package main

import (
	"bufio"
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:2000")
	if err != nil {
		// handle error
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
//	status, err := bufio.NewReader(conn).ReadString('\n')
	_, err = bufio.NewReader(conn).ReadString('\n')
	// ...
}
