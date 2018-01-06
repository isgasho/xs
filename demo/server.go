package main

import (
	"fmt"
	"io"
	"log"
	//"net"
	hkex "blitter.com/herradurakex"
)

func main() {
	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := hkex.Listen("tcp", ":2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	fmt.Println("Serving on port 2000")
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Accepted client")

		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c hkex.HKExConn) {
			// Echo all incoming data.
			io.Copy(c, c)
			fmt.Println("Client sent:%v\n", c)
			// Shut down the connection.
			c.Close()
		}(conn)
	}
}
