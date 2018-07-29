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
	"os/user"
	"runtime"
	"strings"
	"sync"

	hkexsh "blitter.com/go/hkexsh"
	"blitter.com/go/hkexsh/hkexnet"
	isatty "github.com/mattn/go-isatty"
)

type cmdSpec struct {
	op         []byte
	who        []byte
	cmd        []byte
	authCookie []byte
	status     int // though UNIX shell exit status is uint8, os.Exit() wants int
}

var (
	wg      sync.WaitGroup
	defPort = "2000"
)

// Get terminal size using 'stty' command
func GetSize() (cols, rows int, err error) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()

	if err != nil {
		log.Println(err)
		cols, rows = 80, 24 //failsafe
	} else {
		fmt.Sscanf(string(out), "%d %d\n", &rows, &cols)
	}
	return
}

func parseFancyEndpointArg(a []string, dp string) (user, host, port, path string) {
	//TODO: Look for non-option fancyArg of syntax user@host:filespec to set -r,-t and -u
	//  Consider: whether fancyArg is src or dst file depends on flag.Args() index;
	//            fancyArg as last flag.Args() element denotes dstFile
	//            fancyArg as not-last flag.Args() element denotes srcFile
	//            * throw error if >1 fancyArgs are found in flags.Args()
	var fancyUser, fancyHost, fancyPort, fancyPath string
	for i, arg := range flag.Args() {
		if strings.Contains(arg, ":") || strings.Contains(arg, "@") {
			fancyArg := strings.Split(flag.Arg(i), "@")
			var fancyHostPortPath []string
			if len(fancyArg) < 2 {
				//TODO: no user specified, use current
				fancyUser = "[default:getUser]"
				fancyHostPortPath = strings.Split(fancyArg[0], ":")
			} else {
				// user@....
				fancyUser = fancyArg[0]
				fancyHostPortPath = strings.Split(fancyArg[1], ":")
			}

			if len(fancyHostPortPath) > 2 {
				// [user]@host[:port]:path
				fancyPath = fancyHostPortPath[2]
			}
			if len(fancyHostPortPath) > 1 {
				// [user]@host:port[:...] or [user]@host:path (default port)
				fancyPort = fancyHostPortPath[1]
			}
			// [user]@host[:...[:...]]
			fancyHost = fancyHostPortPath[0]

			if fancyPort == "" {
				fancyPort = dp
			}

			if fancyPath == "" {
				fancyPath = "."
			}

			fmt.Println("fancyArgs: user:", fancyUser, "host:", fancyHost, "port:", fancyPort, "path:", fancyPath)
			break // ignore multiple 'fancyArgs'
		}
	}
	return fancyUser, fancyHost, fancyPort, fancyPath
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
	version := "0.1pre (NO WARRANTY)"
	var vopt bool
	var dbg bool
	var cAlg string
	var hAlg string
	var server string
	var cmdStr string

	var copySrc string
	var copyDst string

	var altUser string
	var authCookie string
	var chaffEnabled bool
	var chaffFreqMin uint
	var chaffFreqMax uint
	var chaffBytesMax uint

	var op []byte
	isInteractive := false

	flag.BoolVar(&vopt, "v", false, "show version")
	flag.BoolVar(&dbg, "d", false, "debug logging")
	flag.StringVar(&cAlg, "c", "C_AES_256", "cipher [\"C_AES_256\" | \"C_TWOFISH_128\" | \"C_BLOWFISH_64\"]")
	flag.StringVar(&hAlg, "m", "H_SHA256", "hmac [\"H_SHA256\"]")
	flag.StringVar(&server, "s", "localhost:"+defPort, "server hostname/address[:port]")
	flag.StringVar(&altUser, "u", "", "specify alternate user")
	flag.StringVar(&authCookie, "a", "", "auth cookie")
	flag.BoolVar(&chaffEnabled, "e", true, "enabled chaff pkts (default true)")
	flag.UintVar(&chaffFreqMin, "f", 100, "chaff pkt freq min (msecs)")
	flag.UintVar(&chaffFreqMax, "F", 5000, "chaff pkt freq max (msecs)")
	flag.UintVar(&chaffBytesMax, "B", 64, "chaff pkt size max (bytes)")

	// Find out what program we are (shell or copier)
	myPath := strings.Split(os.Args[0], string(os.PathSeparator))
	if myPath[len(myPath)-1] != "hkexcp" && myPath[len(myPath)-1] != "hkexcp.exe" {
		// hkexsh accepts a command (-x) but not
		// a srcpath (-r) or dstpath (-t)
		flag.StringVar(&cmdStr, "x", "", "command to run (default empty - interactive shell)")
	} else {
		// hkexcp accepts srcpath (-r) and dstpath (-t), but not
		// a command (-x)
		flag.StringVar(&copySrc, "r", "", "copy srcpath")
		flag.StringVar(&copyDst, "t", "", "copy dstpath")
	}
	flag.Parse()

	fancyUser, fancyHost, fancyPort, fancyPath := parseFancyEndpointArg(flag.Args(), defPort /* defPort */)
	fmt.Println("fancyHost:", fancyHost)
	if fancyUser != "" {
		altUser = fancyUser
	}
	if fancyHost != "" {
		server = fancyHost + ":" + fancyPort
		fmt.Println("fancyHost sets server to", server)
	}
	if fancyPath != "" {
		//TODO: srcPath or dstPath depends on other flag.Args
		copyDst = fancyPath
	}

	fmt.Println("server finally is:", server)

	if flag.NFlag() == 0 && server == "" {
		flag.Usage()
		os.Exit(0)
	}

	if vopt {
		fmt.Printf("version v%s\n", version)
		os.Exit(0)
	}

	if len(cmdStr) != 0 && (len(copySrc) != 0 || len(copyDst) != 0) {
		log.Fatal("incompatible options -- either cmd (-x) or copy ops (-r,-t), but not both")
	}

	if dbg {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	conn, err := hkexnet.Dial("tcp", server, cAlg, hAlg)
	if err != nil {
		fmt.Println("Err!")
		panic(err)
	}
	defer conn.Close()
	// From this point on, conn is a secure encrypted channel

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

	if len(cmdStr) == 0 {
		op = []byte{'s'}
		isInteractive = true
	} else {
		op = []byte{'c'}
		// non-interactive cmds may complete quickly, so chaff earlier/faster
		// to help ensure there's some cover to the brief traffic.
		// (ignoring cmdline values)
		chaffFreqMin = 2
		chaffFreqMax = 10
	}

	if len(authCookie) == 0 {
		fmt.Printf("Gimme cookie:")
		ab, err := hkexsh.ReadPassword(int(os.Stdin.Fd()))
		fmt.Printf("\r\n")
		if err != nil {
			panic(err)
		}
		authCookie = string(ab)
		// Security scrub
		ab = nil
		runtime.GC()
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

	// Set up chaffing to server
	conn.SetupChaff(chaffFreqMin, chaffFreqMax, chaffBytesMax) // enable client->server chaffing
	if chaffEnabled {
		conn.EnableChaff()
	}
	defer conn.DisableChaff()
	defer conn.ShutdownChaff()

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

		rec.status = int(conn.GetStatus())
		log.Println("rec.status:", rec.status)

		if isInteractive {
			log.Println("[* Got EOF *]")
			_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
			wg.Done()
			//os.Exit(rec.status)
		}
	}()

	if isInteractive {
		handleTermResizes(conn)

		// client writer (to server) goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Copy() expects EOF so this will
			// exit with outerr == nil
			//!_, outerr := io.Copy(conn, os.Stdin)
			_, outerr := func(conn *hkexnet.Conn, r io.Reader) (w int64, e error) {
				return io.Copy(conn, r)
			}(conn, os.Stdin)

			if outerr != nil {
				log.Println(outerr)
				if outerr.Error() != "EOF" {
					fmt.Println(outerr)
					_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
					os.Exit(255)
				}
			}
			log.Println("[Sent EOF]")
			wg.Done() // client hung up, close WaitGroup to exit client
		}()
	}

	// Wait until both stdin and stdout goroutines finish
	wg.Wait()

	_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
	os.Exit(rec.status)
}
