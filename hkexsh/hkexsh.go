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
	status     int // UNIX exit status is uint8, but os.Exit() wants int
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

func parseNonSwitchArgs(a []string, dp string) (user, host, port, path string, isDest bool, otherArgs []string) {
	//TODO: Look for non-option fancyArg of syntax user@host:filespec to set -r,-t and -u
	//  Consider: whether fancyArg is src or dst file depends on flag.Args() index;
	//            fancyArg as last flag.Args() element denotes dstFile
	//            fancyArg as not-last flag.Args() element denotes srcFile
	//            * throw error if >1 fancyArgs are found in flags.Args()
	var fancyUser, fancyHost, fancyPort, fancyPath string
	for i, arg := range a {
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

			// [...@]host[:port[:path]]
			if len(fancyHostPortPath) > 2 {
				fancyPath = fancyHostPortPath[2]
			} else if len(fancyHostPortPath) > 1 {
				fancyPort = fancyHostPortPath[1]
			}
			fancyHost = fancyHostPortPath[0]

			if fancyPort == "" {
				fancyPort = dp
			}

			//if fancyPath == "" {
			//	fancyPath = "."
			//}

			if i == len(a)-1 {
				isDest = true
				fmt.Println("remote path isDest")
			}
			fmt.Println("fancyArgs: user:", fancyUser, "host:", fancyHost, "port:", fancyPort, "path:", fancyPath)
		} else {
			otherArgs = append(otherArgs, a[i])
		}
	}
	return fancyUser, fancyHost, fancyPort, fancyPath, isDest, otherArgs
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
	var shellMode bool // if true act as shell, else file copier
	var cAlg string
	var hAlg string
	var server string
	var cmdStr string

	var copySrc []byte
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
		shellMode = true
	} // else {
	//// hkexcp accepts srcpath (-r) and dstpath (-t), but not
	//// a command (-x)
	//flag.StringVar(&copySrc, "r", "", "copy srcpath")
	//flag.StringVar(&copyDst, "t", "", "copy dstpath")
	//}
	flag.Parse()

	tmpUser, tmpHost, tmpPort, tmpPath, pathIsDest, otherArgs :=
		parseNonSwitchArgs(flag.Args(), defPort /* defPort */)
	fmt.Println("otherArgs:", otherArgs)
	//fmt.Println("tmpHost:", tmpHost)
	//fmt.Println("tmpPath:", tmpPath)
	if tmpUser != "" {
		altUser = tmpUser
	}
	if tmpHost != "" {
		server = tmpHost + ":" + tmpPort
		//fmt.Println("tmpHost sets server to", server)
	}
	if tmpPath != "" {
		// -if pathIsSrc && len(otherArgs) > 1 ERROR
		// -else flatten otherArgs into space-delim list => copySrc
		if pathIsDest {
			for _, v := range otherArgs {
				copySrc = append(copySrc, ' ')
				copySrc = append(copySrc, v...)
			}
			fmt.Println(">> copySrc:", string(copySrc))
			copyDst = tmpPath
		} else {
			if len(otherArgs) > 1 {
				log.Fatal("ERROR: cannot specify more than one dest path for copy")
			}
			copySrc = []byte(tmpPath)
		}
	}

	// Do some more option consistency checks

	//fmt.Println("server finally is:", server)
	if flag.NFlag() == 0 && server == "" {
		flag.Usage()
		os.Exit(0)
	}

	if vopt {
		fmt.Printf("version v%s\n", version)
		os.Exit(0)
	}

	if len(cmdStr) != 0 && (len(copySrc) != 0 || len(copyDst) != 0) {
		log.Fatal("incompatible options -- either cmd (-x) or copy ops but not both")
	}

	//-------------------------------------------------------------------
	// Here we have parsed all options and can now carry out
	// either the shell session or copy operation.
	_ = shellMode

	if dbg {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	// We must make the decision about interactivity before Dial()
	// as it affects chaffing behaviour. 20180805
	if len(cmdStr) == 0 {
		op = []byte{'s'}
		isInteractive = true
	} else {
		op = []byte{'c'}
		// non-interactive cmds may complete quickly, so chaff earlier/faster
		// to help ensure there's some cover to the brief traffic.
		// (ignoring cmdline values)
		//!DEBUG
		//chaffEnabled = false
		chaffFreqMin = 2
		chaffFreqMax = 10
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
	if shellMode {
		if isatty.IsTerminal(os.Stdin.Fd()) {
			oldState, err = hkexsh.MakeRaw(int(os.Stdin.Fd()))
			if err != nil {
				panic(err)
			}
			defer func() { _ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.
		} else {
			log.Println("NOT A TTY")
		}
	}

	var uname string
	if len(altUser) == 0 {
		u, _ := user.Current()
		uname = u.Username
	} else {
		uname = altUser
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
		defer conn.DisableChaff()
		defer conn.ShutdownChaff()
	}

	//client reader (from server) goroutine
	//Read remote end's stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		// By deferring a call to wg.Done(),
		// each goroutine guarantees that it marks
		// its direction's stream as finished.

		// io.Copy() expects EOF so normally this will
		// exit with inerr == nil
		_, inerr := io.Copy(os.Stdout, conn)
		if inerr != nil {
			fmt.Println(inerr)
			_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
			os.Exit(1)
		}

		rec.status = int(conn.GetStatus())
		log.Println("rec.status:", rec.status)

		if isInteractive {
			log.Println("[* Got EOF *]")
			_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
		}
	}()

	// Only look for data from stdin to send to remote end
	// for interactive sessions.
	if isInteractive {
		handleTermResizes(conn)

		// client writer (to server) goroutine
		// Write local stdin to remote end
		wg.Add(1)
		go func() {
			defer wg.Done()
			//!defer wg.Done()
			// Copy() expects EOF so this will
			// exit with outerr == nil
			//!_, outerr := io.Copy(conn, os.Stdin)
			_, outerr := func(conn *hkexnet.Conn, r io.Reader) (w int64, e error) {
				w, e = io.Copy(conn, r)
				return w, e
			}(conn, os.Stdin)

			if outerr != nil {
				log.Println(outerr)
				fmt.Println(outerr)
				_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
				os.Exit(255)
			}
			log.Println("[Sent EOF]")
		}()
	}

	// Wait until both stdin and stdout goroutines finish
	// ** IMPORTANT! This must come before the Restore() tty call below
	// in order to maintain raw mode for interactive sessions. -rlm 20180805
	wg.Wait()
	
	_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.

	os.Exit(rec.status)
}
