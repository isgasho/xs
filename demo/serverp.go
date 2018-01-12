package main

import (
	"fmt"
	"log"
	"time"

	"net"
)

func main() {
	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := net.Listen("tcp", ":2000")
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
		go func(c net.Conn) (e error) {
			ch := make(chan []byte)
			chN := 0
			eCh := make(chan error)

			// Start a goroutine to read from our net connection
			go func(ch chan []byte, eCh chan error) {
				for {
					// try to read the data
					data := make([]byte, 512)
					chN, err = c.Read(data)
					if err != nil {
						// send an error if it's encountered
						eCh <- err
						return
					}
					// send data if we read some.
					ch <- data[0:chN]
				}
			}(ch, eCh)

			ticker := time.Tick(time.Second)
		Term:
			// continuously read from the connection
			for {
				select {
				// This case means we recieved data on the connection
				case data := <-ch:
					// Do something with the data
					fmt.Printf("Client sent %+v\n", data[0:chN])
					//fmt.Printf("Client sent %s\n", string(data))
				// This case means we got an error and the goroutine has finished
				case err := <-eCh:
					// handle our error then exit for loop
					if err.Error() == "EOF" {
						fmt.Printf("[Client disconnected]\n")
					} else {
						fmt.Printf("Error reading client data! (%+v)\n", err)
					}
					break Term
				// This will timeout on the read.
				case <-ticker:
					// do nothing? this is just so we can time out if we need to.
					// you probably don't even need to have this here unless you want
					// do something specifically on the timeout.
				}
			}
			// Shut down the connection.
			c.Close()
			return
		}(conn)
	}
}