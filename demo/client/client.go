package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"

	hkex "blitter.com/herradurakex"
)

// Demo of a simple client that dials up to a simple test server to
// send data.
//
// While conforming to the basic net.Conn interface HKex.Conn has extra
// capabilities designed to allow apps to define connection options,
// encryption/hmac settings and operations across the encrypted channel.
//
// Initial setup is the same as using plain net.Dial(), but one may
// specify extra extension tags (strings) to set the cipher and hmac
// setting desired; as well as the intended operation mode for the
// connection (app-specific, passed through to the server to use or
// ignore at its discretion).
func main() {
	var wg sync.WaitGroup

	var cAlg string
	var hAlg string
	var server string

	flag.StringVar(&cAlg, "c", "C_AES_256", "cipher [\"C_AES_256\" | \"C_TWOFISH_128\" | \"C_BLOWFISH_64\"]")
	flag.StringVar(&hAlg, "h", "H_SHA256", "hmac [\"H_SHA256\"]")
	flag.StringVar(&server, "s", "localhost:2000", "server hostname/address[:port]")
	flag.Parse()

	log.SetOutput(ioutil.Discard)

	conn, err := hkex.Dial("tcp", server, cAlg, hAlg)
	if err != nil {
		fmt.Println("Err!")
		panic(err)
	}
	defer conn.Close()

	wg.Add(1)
	go func() {
		// This will guarantee the side that closes first
		// marks its direction's goroutine as finished.
		// Whichever direction's goroutine finishes first
		// will call wg.Done() once more explicitly to
		// hang up on the other side so the client
		// exits immediately on an EOF from either side.
		defer wg.Done()

		// io.Copy() expects EOF so this will
		// exit with inerr == nil
		_, inerr := io.Copy(os.Stdout, conn)
		if inerr != nil {
			if inerr.Error() != "EOF" {
				fmt.Println(inerr)
				os.Exit(1)
			}
		}
		fmt.Println("[Got Write EOF]")
		wg.Done() // client hanging up, close server read goroutine
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		// io.Copy() expects EOF so this will
		// exit with outerr == nil
		_, outerr := io.Copy(conn, os.Stdin)
		if outerr != nil {
			if outerr.Error() != "EOF" {
				fmt.Println(outerr)
				os.Exit(2)
			}
		}
		fmt.Println("[Got Read EOF]")
		wg.Done() // server hung up, close client write goroutine
	}()

	// Wait until both stdin and stdout goroutines finish
	wg.Wait()
}
