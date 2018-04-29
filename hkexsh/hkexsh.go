// hkexsh client
//
// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strings"
	"sync"
	"syscall"

	hkexsh "blitter.com/go/hkexsh"
	isatty "github.com/mattn/go-isatty"
)

type cmdSpec struct {
	op         []byte
	who        []byte
	cmd        []byte
	authCookie []byte
	status     int
}

// get terminal size using 'stty' command
// (Most portable btwn Linux and MSYS/win32, but
//  TODO: remove external dep on 'stty' utility)
func getTermSize() (rows int, cols int, err error) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	//fmt.Printf("out: %#v\n", string(out))
	//fmt.Printf("err: %#v\n", err)

	fmt.Sscanf(string(out), "%d %d\n", &rows, &cols)
	if err != nil {
		log.Fatal(err)
	}
	return
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

	conn, err := hkexsh.Dial("tcp", server, cAlg, hAlg)
	if err != nil {
		fmt.Println("Err!")
		panic(err)
	}
	defer conn.Close()
	// From this point on, conn is a secure encrypted channel

	rows := 0
	cols := 0

	// Set stdin in raw mode if it's an interactive session
	// TODO: send flag to server side indicating this
	//  affects shell command used
	var oldState *hkexsh.State
	if isatty.IsTerminal(os.Stdin.Fd()) {
		oldState, err = hkexsh.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			panic(err)
		}
		defer func() { _ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.
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
		ab, err := hkexsh.ReadPassword(int(os.Stdin.Fd()))
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

	_, err = fmt.Fprintf(conn, "%d %d %d %d\n",
		len(rec.op), len(rec.who), len(rec.cmd), len(rec.authCookie))

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
				_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
				os.Exit(1)
			}
		}

		if isInteractive {
			log.Println("[Got EOF]")
			wg.Done() // server hung up, close WaitGroup to exit client
		}
	}()

	if isInteractive {
		// Handle pty resizes (notify server side)
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGWINCH)
		wg.Add(1)
		go func() {
			defer wg.Done()

			for range ch {
				// Query client's term size so we can communicate it to server
				// pty after interactive session starts
				rows, cols, err = getTermSize()
				log.Printf("[rows %v cols %v]\n", rows, cols)
				if err != nil {
					panic(err)
				}
				termSzPacket := fmt.Sprintf("%d %d", rows, cols)
				conn.WritePacket([]byte(termSzPacket), hkexsh.CSOTermSize)
			}
		}()
		ch <- syscall.SIGWINCH // Initial resize.

		// client writer (to server) goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()

			// io.Copy() expects EOF so this will
			// exit with outerr == nil
			_, outerr := io.Copy(conn, os.Stdin)
			if outerr != nil {
				log.Println(outerr)
				if outerr.Error() != "EOF" {
					fmt.Println(outerr)
					_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
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
