package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strings"
	"sync"

	hkex "blitter.com/hkexsh"
	isatty "github.com/mattn/go-isatty"
)

type cmdSpec struct {
	op         []byte
	who        []byte
	cmd        []byte
	authCookie []byte
	status     int
}

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

	var dbg bool
	var cAlg string
	var hAlg string
	var server string
	var cmdStr string
	var altUser string
	var authCookie string
	isInteractive := false

	flag.StringVar(&cAlg, "c", "C_AES_256", "cipher [\"C_AES_256\" | \"C_TWOFISH_128\" | \"C_BLOWFISH_64\"]")
	flag.StringVar(&hAlg, "h", "H_SHA256", "hmac [\"H_SHA256\"]")
	flag.StringVar(&server, "s", "localhost:2000", "server hostname/address[:port]")
	flag.StringVar(&cmdStr, "x", "", "command to run (default empty - interactive shell)")
	flag.StringVar(&altUser, "u", "", "specify alternate user")
	flag.StringVar(&authCookie, "a", "", "auth cookie (MultiCheese3999(tm) 2FA cookie")
	flag.BoolVar(&dbg, "d", false, "debug logging")
	flag.Parse()

	if dbg {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	conn, err := hkex.Dial("tcp", server, cAlg, hAlg)
	if err != nil {
		fmt.Println("Err!")
		panic(err)
	}
	defer conn.Close()
	// From this point on, conn is a secure encrypted channel

	// Set stdin in raw mode if it's an interactive session
	// TODO: send flag to server side indicating this
	//  affects shell command used
	if isatty.IsTerminal(os.Stdin.Fd()) {
		oldState, err := hkex.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			panic(err)
		}
		defer func() { _ = hkex.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.
	} else {
		log.Println("NOT A TTY")
	}

	var uname string
	if len(altUser) == 0 {
		u, _ := user.Current()
		uname = u.Username
	} else {
		uname = altUser
	}

	var op []byte
	if len(cmdStr) == 0 {
		op = []byte{'s'}
		isInteractive = true
	} else if cmdStr == "-" {
		op = []byte{'c'}
		cmdStdin, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}
		cmdStr = strings.Trim(string(cmdStdin), "\r\n")
	} else {
		op = []byte{'c'}
	}

	if len(authCookie) == 0 {
		fmt.Printf("Gimme cookie:")
		ab, err := hkex.ReadPassword(int(os.Stdin.Fd()))
		fmt.Printf("\r\n")
		if err != nil {
			panic(err)
		}
		authCookie = string(ab)
	}

	rec := &cmdSpec{
		op:         op,
		who:        []byte(uname),
		cmd:        []byte(cmdStr),
		authCookie: []byte(authCookie),
		status:     0}

	_, err = fmt.Fprintf(conn, "%d %d %d %d\n", len(rec.op), len(rec.who), len(rec.cmd), len(rec.authCookie))
	_, err = conn.Write(rec.op)
	_, err = conn.Write(rec.who)
	_, err = conn.Write(rec.cmd)
	_, err = conn.Write(rec.authCookie)

	//client reader (from server) goroutine
	wg.Add(1)
	go func() {
		// By deferring a call to wg.Done(),
		// each goroutine guarantees that it marks
		// its direction's stream as finished.
		//
		// Whichever direction's goroutine finishes first
		// will call wg.Done() once more, explicitly, to
		// hang up on the other side, so that this client
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
		if isInteractive {
			log.Println("[Got EOF]")
			wg.Done() // server hung up, close WaitGroup to exit client
		}
	}()

	if isInteractive {
		// client writer (to server) goroutine
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
			log.Println("[Sent EOF]")
			wg.Done() // client hung up, close WaitGroup to exit client
		}()
	}

	// Wait until both stdin and stdout goroutines finish
	wg.Wait()
}
