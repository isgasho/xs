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
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

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
	wg sync.WaitGroup
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

func parseNonSwitchArgs(a []string) (user, host, path string, isDest bool, otherArgs []string) {
	// Whether fancyArg is src or dst file depends on flag.Args() index;
	//  fancyArg as last flag.Args() element denotes dstFile
	//  fancyArg as not-last flag.Args() element denotes srcFile
	var fancyUser, fancyHost, fancyPath string
	for i, arg := range a {
		if strings.Contains(arg, ":") || strings.Contains(arg, "@") {
			fancyArg := strings.Split(flag.Arg(i), "@")
			var fancyHostPath []string
			if len(fancyArg) < 2 {
				//TODO: no user specified, use current
				fancyUser = "[default:getUser]"
				fancyHostPath = strings.Split(fancyArg[0], ":")
			} else {
				// user@....
				fancyUser = fancyArg[0]
				fancyHostPath = strings.Split(fancyArg[1], ":")
			}

			// [...@]host[:path]
			if len(fancyHostPath) > 1 {
				fancyPath = fancyHostPath[1]
			}
			fancyHost = fancyHostPath[0]

			//if fancyPath == "" {
			//	fancyPath = "."
			//}

			if i == len(a)-1 {
				isDest = true
				fmt.Println("remote path isDest")
			}
			fmt.Println("fancyArgs: user:", fancyUser, "host:", fancyHost, "path:", fancyPath)
		} else {
			otherArgs = append(otherArgs, a[i])
		}
	}
	return fancyUser, fancyHost, fancyPath, isDest, otherArgs
}

// doCopyMode begins a secure hkexsh local<->remote file copy operation.
func doCopyMode(conn *hkexnet.Conn, remoteDest bool, files string, rec *cmdSpec) (err error, exitStatus int) {
	if remoteDest {
		fmt.Println("local files:", files, "remote filepath:", string(rec.cmd))

		var c *exec.Cmd

		//os.Clearenv()
		//os.Setenv("HOME", u.HomeDir)
		//os.Setenv("TERM", "vt102") // TODO: server or client option?

		cmdName := "/bin/tar"
		cmdArgs := []string{"-c", "-f", "/dev/stdout"}
		files = strings.TrimSpace(files)
		// Awesome fact: tar actually can take multiple -C args, and
		// changes to the dest dir *as it sees each one*. This enables
		// its use below, where clients can send scattered sets of source
		// files and dirs to be extracted to a single dest dir server-side,
		// whilst preserving the subtrees of dirs on the other side.
		// Eg., tar -c -f /dev/stdout -C /dirA fileInA -C /some/where/dirB fileInB /foo/dirC
		// packages fileInA, fileInB, and dirC at a single toplevel in the tar.
		// The tar authors are/were real smarties :)
		//
		// This is the 'scatter/gather' logic to allow specification of
		// files and dirs in different trees to be deposited in a single
		// remote destDir.
		for _, v := range strings.Split(files, " ") {
			v, _ = filepath.Abs(v)
			dirTmp, fileTmp := path.Split(v)
			if dirTmp == "" {
				cmdArgs = append(cmdArgs, fileTmp)
			} else {
				cmdArgs = append(cmdArgs, "-C", dirTmp, fileTmp)
			}
			//cmdArgs = append(cmdArgs, v)
		}

		fmt.Printf("[%v %v]\n", cmdName, cmdArgs)
		// NOTE the lack of quotes around --xform option's sed expression.
		// When args are passed in exec() format, no quoting is required
		// (as this isn't input from a shell) (right? -rlm 20180823)
		//cmdArgs := []string{"-xvz", "-C", files, `--xform=s#.*/\(.*\)#\1#`}
		c = exec.Command(cmdName, cmdArgs...)
		c.Dir, _ = os.Getwd()
		fmt.Println("[wd:", c.Dir, "]")
		c.Stdout = conn
		// Stderr sinkholing is important. Any extraneous output to tarpipe
		// messes up remote side as it's expecting pure tar data.
		// (For example, if user specifies abs paths, tar outputs
		// "Removing leading '/' from path names")
		c.Stderr = nil

		// Start the command (no pty)
		err = c.Start() // returns immediately
		if err != nil {
			fmt.Println(err)
			//log.Fatal(err)
		} else {
			if err = c.Wait(); err != nil {
				if exiterr, ok := err.(*exec.ExitError); ok {
					// The program has exited with an exit code != 0

					// This works on both Unix and Windows. Although package
					// syscall is generally platform dependent, WaitStatus is
					// defined for both Unix and Windows and in both cases has
					// an ExitStatus() method with the same signature.
					if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
						exitStatus = status.ExitStatus()
						log.Printf("Exit Status: %d", exitStatus)
					}
				}
			}
			fmt.Println("*** client->server cp finished ***")
		}
	} else {
		fmt.Println("remote filepath:", string(rec.cmd), "local files:", files)
		var c *exec.Cmd

		//os.Clearenv()
		//os.Setenv("HOME", u.HomeDir)
		//os.Setenv("TERM", "vt102") // TODO: server or client option?

		cmdName := "/bin/tar"
		destPath := files

		cmdArgs := []string{"-x", "-C", destPath}
		fmt.Printf("[%v %v]\n", cmdName, cmdArgs)
		// NOTE the lack of quotes around --xform option's sed expression.
		// When args are passed in exec() format, no quoting is required
		// (as this isn't input from a shell) (right? -rlm 20180823)
		//cmdArgs := []string{"-xvz", "-C", destPath, `--xform=s#.*/\(.*\)#\1#`}
		c = exec.Command(cmdName, cmdArgs...)
		c.Stdin = conn
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		// Start the command (no pty)
		err = c.Start() // returns immediately
		if err != nil {
			fmt.Println(err)
			//log.Fatal(err)
		} else {
			if err = c.Wait(); err != nil {
				if exiterr, ok := err.(*exec.ExitError); ok {
					// The program has exited with an exit code != 0

					// This works on both Unix and Windows. Although package
					// syscall is generally platform dependent, WaitStatus is
					// defined for both Unix and Windows and in both cases has
					// an ExitStatus() method with the same signature.
					if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
						exitStatus = status.ExitStatus()
						log.Printf("Exit Status: %d", exitStatus)
					}
				}
			}
			fmt.Println("*** server->client cp finished ***")
		}
	}
	return
}

// doShellMode begins an hkexsh shell session (one-shot command or interactive).
func doShellMode(isInteractive bool, conn *hkexnet.Conn, oldState *hkexsh.State, rec *cmdSpec) {
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

	// Wait until both stdin and stdout goroutines finish before returning
	// (ensure client gets all data from server before closing)
	wg.Wait()
}

func UsageShell() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "%s [opts] [user]@server\n", os.Args[0])
	flag.PrintDefaults()
}

func UsageCp() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "%s [opts] srcFileOrDir [...] [user]@server[:dstpath]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "%s [opts] [user]@server[:srcFileOrDir] dstPath\n", os.Args[0])
	flag.PrintDefaults()
}

// hkexsh - a client for secure shell and file copy operations.
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
	var port uint
	var cmdStr string

	var copySrc []byte
	var copyDst string

	var authCookie string
	var chaffEnabled bool
	var chaffFreqMin uint
	var chaffFreqMax uint
	var chaffBytesMax uint

	var op []byte
	isInteractive := false

	flag.BoolVar(&vopt, "v", false, "show version")
	flag.BoolVar(&dbg, "d", false, "debug logging")
	flag.StringVar(&cAlg, "c", "C_AES_256", "`cipher` [\"C_AES_256\" | \"C_TWOFISH_128\" | \"C_BLOWFISH_64\"]")
	flag.StringVar(&hAlg, "m", "H_SHA256", "`hmac` [\"H_SHA256\"]")
	flag.UintVar(&port, "p", 2000, "`port`")
	flag.StringVar(&authCookie, "a", "", "auth cookie")
	flag.BoolVar(&chaffEnabled, "e", true, "enabled chaff pkts (default true)")
	flag.UintVar(&chaffFreqMin, "f", 100, "chaff pkt `freq` min (msecs)")
	flag.UintVar(&chaffFreqMax, "F", 5000, "chaff pkt `freq` max (msecs)")
	flag.UintVar(&chaffBytesMax, "B", 64, "chaff pkt `size` max (bytes)")

	// Find out what program we are (shell or copier)
	myPath := strings.Split(os.Args[0], string(os.PathSeparator))
	if myPath[len(myPath)-1] != "hkexcp" && myPath[len(myPath)-1] != "hkexcp.exe" {
		// hkexsh accepts a command (-x) but not
		// a srcpath (-r) or dstpath (-t)
		flag.StringVar(&cmdStr, "x", "", "`command` to run (if not specified run interactive shell)")
		shellMode = true
		flag.Usage = UsageShell
	} else {
		flag.Usage = UsageCp
	}
	flag.Parse()

	remoteUser, tmpHost, tmpPath, pathIsDest, otherArgs :=
		parseNonSwitchArgs(flag.Args())
	fmt.Println("otherArgs:", otherArgs)

	// Set defaults if user doesn't specify user, path or port
	var uname string
	if remoteUser == "" {
		u, _ := user.Current()
		uname = u.Username
	} else {
		uname = remoteUser
	}

	if tmpHost != "" {
		server = tmpHost + ":" + fmt.Sprintf("%d", port)
	}
	if tmpPath == "" {
		tmpPath = "."
	}

	var fileArgs string
	if !shellMode /*&& tmpPath != ""*/ {
		// -if pathIsSrc && len(otherArgs) > 1 ERROR
		// -else flatten otherArgs into space-delim list => copySrc
		if pathIsDest {
			if len(otherArgs) == 0 {
				log.Fatal("ERROR: Must specify at least one dest path for copy")
			} else {
				for _, v := range otherArgs {
					copySrc = append(copySrc, ' ')
					copySrc = append(copySrc, v...)
				}
				copyDst = tmpPath
				fileArgs = string(copySrc)
			}
		} else {
			if len(otherArgs) == 0 {
				log.Fatal("ERROR: Must specify src path for copy")
			} else if len(otherArgs) == 1 {
				copyDst = otherArgs[0]
				if strings.Contains(copyDst, "*") || strings.Contains(copyDst, "?") {
					log.Fatal("ERROR: wildcards not allowed in dest path for copy")
				}
			} else {
				log.Fatal("ERROR: cannot specify more than one dest path for copy")
			}
			copySrc = []byte(tmpPath)
			fileArgs = copyDst
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

	if shellMode {
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
			chaffFreqMin = 2
			chaffFreqMax = 10
		}
	} else {
		// as copy mode is also non-interactive, set up chaffing
		// just like the 'c' mode above
		chaffFreqMin = 2
		chaffFreqMax = 10

		if pathIsDest {
			// client->server file copy
			// src file list is in copySrc
			op = []byte{'D'}
			fmt.Println("client->server copy:", string(copySrc), "->", copyDst)
			cmdStr = copyDst
		} else {
			// server->client file copy
			// remote src file(s) in copyDsr
			op = []byte{'S'}
			fmt.Println("server->client copy:", string(copySrc), "->", copyDst)
			cmdStr = string(copySrc)
		}
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

	if shellMode {
		doShellMode(isInteractive, conn, oldState, rec)
	} else {
		doCopyMode(conn, pathIsDest, fileArgs, rec)
	}

	if oldState != nil {
		_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
	}

	os.Exit(rec.status)
}
