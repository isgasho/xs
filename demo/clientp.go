package main

import (
	"fmt"

	"net"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:2000")
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