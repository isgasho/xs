package main

import (
	"fmt"

	hkex "blitter.com/herradurakex"
)

func main() {
	conn, err := hkex.Dial("tcp", "localhost:2000")
	if err != nil {
		// handle error
	}
	fmt.Printf("conn: %v\n", conn)
//		fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
//		status, err := bufio.NewReader(conn).ReadString('\n')
//		_, err = bufio.NewReader(conn).ReadString('\n')
	// ...
}
