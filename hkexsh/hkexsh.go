// hkexsh client
//
// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	hkexsh "blitter.com/go/hkexsh"
	"blitter.com/go/hkexsh/hkexnet"
	"blitter.com/go/hkexsh/logger"
	"blitter.com/go/hkexsh/spinsult"
	isatty "github.com/mattn/go-isatty"
)

var (
	wg sync.WaitGroup
	// Log defaults to regular syslog output (no -d)
	Log *logger.Writer
)

// GetSize gets the terminal size using 'stty' command
func GetSize() (cols, rows int, err error) {
	cmd := exec.Command("stty", "size") // #nosec
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()

	if err != nil {
		log.Println(err)
		cols, rows = 80, 24 //failsafe
	} else {
		n, err := fmt.Sscanf(string(out), "%d %d\n", &rows, &cols)
		if n < 2 ||
			rows < 0 ||
			cols < 0 ||
			rows > 9000 ||
			cols > 9000 ||
			err != nil {
			log.Printf("GetSize error: rows:%d cols:%d; %v\n",
				rows, cols, err)
		}
	}
	return
}

// doCopyMode begins a secure hkexsh local<->remote file copy operation.
func doCopyMode(conn *hkexnet.Conn, remoteDest bool, files string, rec *hkexsh.Session) (exitStatus uint32, err error) {
	if remoteDest {
		log.Println("local files:", files, "remote filepath:", string(rec.Cmd()))

		var c *exec.Cmd

		//os.Clearenv()
		//os.Setenv("HOME", u.HomeDir)
		//os.Setenv("TERM", "vt102") // TODO: server or client option?

		cmdName := "/bin/tar"
		cmdArgs := []string{"-cz", "-f", "/dev/stdout"}
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
			v, _ = filepath.Abs(v) // #nosec
			dirTmp, fileTmp := path.Split(v)
			if dirTmp == "" {
				cmdArgs = append(cmdArgs, fileTmp)
			} else {
				cmdArgs = append(cmdArgs, "-C", dirTmp, fileTmp)
			}
		}

		log.Printf("[%v %v]\n", cmdName, cmdArgs)
		// NOTE the lack of quotes around --xform option's sed expression.
		// When args are passed in exec() format, no quoting is required
		// (as this isn't input from a shell) (right? -rlm 20180823)
		//cmdArgs := []string{"-xvz", "-C", files, `--xform=s#.*/\(.*\)#\1#`}
		c = exec.Command(cmdName, cmdArgs...) // #nosec
		c.Dir, _ = os.Getwd()                 // #nosec
		log.Println("[wd:", c.Dir, "]")
		c.Stdout = conn
		stdErrBuffer := new(bytes.Buffer)
		c.Stderr = stdErrBuffer

		// Start the command (no pty)
		err = c.Start() // returns immediately
		/////////////
		// NOTE: There is, apparently, a bug in Go stdlib here. Start()
		// can actually return immediately, on a command which *does*
		// start but exits quickly, with c.Wait() error
		// "c.Wait status: exec: not started".
		// As in this example, attempting a client->server copy to
		// a nonexistent remote dir (it's tar exiting right away, exitStatus
		// 2, stderr
		// /bin/tar -xz -C /home/someuser/nosuchdir
		// stderr: fork/exec /bin/tar: no such file or directory
		//
		// In this case, c.Wait() won't give us the real
		// exit status (is it lost?).
		/////////////
		if err != nil {
			fmt.Println("cmd exited immediately. Cannot get cmd.Wait().ExitStatus()")
			err = errors.New("cmd exited prematurely")
			exitStatus = uint32(2)
		} else {
			if err = c.Wait(); err != nil {
				if exiterr, ok := err.(*exec.ExitError); ok {
					// The program has exited with an exit code != 0

					// This works on both Unix and Windows. Although package
					// syscall is generally platform dependent, WaitStatus is
					// defined for both Unix and Windows and in both cases has
					// an ExitStatus() method with the same signature.
					if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
						exitStatus = uint32(status.ExitStatus())
						fmt.Print(stdErrBuffer)
						fmt.Printf("Exit Status: %d\n", exitStatus) //#
					}
				}
			}
			// send CSOExitStatus to inform remote (server) end cp is done
			log.Println("Sending local exitStatus:", exitStatus)
			r := make([]byte, 4)
			binary.BigEndian.PutUint32(r, exitStatus)
			_, we := conn.WritePacket(r, hkexnet.CSOExitStatus)
			if we != nil {
				fmt.Println("Error:", we)
			}

			// Do a final read for remote's exit status
			s := make([]byte, 4)
			_, remErr := conn.Read(s)
			if remErr != io.EOF &&
				!strings.Contains(remErr.Error(), "use of closed network") &&
				!strings.Contains(remErr.Error(), "connection reset by peer") {
				fmt.Printf("*** remote status Read() failed: %v\n", remErr)
			} else {
				conn.SetStatus(0) // cp finished OK
			}

			// If local side status was OK, use remote side's status
			if exitStatus == 0 {
				exitStatus = uint32(conn.GetStatus())
				log.Println("Received remote exitStatus:", exitStatus)
			}
			log.Printf("*** client->server cp finished , status %d ***\n", conn.GetStatus())
		}
	} else {
		log.Println("remote filepath:", string(rec.Cmd()), "local files:", files)
		var c *exec.Cmd

		//os.Clearenv()
		//os.Setenv("HOME", u.HomeDir)
		//os.Setenv("TERM", "vt102") // TODO: server or client option?

		cmdName := "/bin/tar"
		destPath := files

		cmdArgs := []string{"-xz", "-C", destPath}
		log.Printf("[%v %v]\n", cmdName, cmdArgs)
		// NOTE the lack of quotes around --xform option's sed expression.
		// When args are passed in exec() format, no quoting is required
		// (as this isn't input from a shell) (right? -rlm 20180823)
		//cmdArgs := []string{"-xvz", "-C", destPath, `--xform=s#.*/\(.*\)#\1#`}
		c = exec.Command(cmdName, cmdArgs...) // #nosec
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
						exitStatus = uint32(status.ExitStatus())
						log.Printf("Exit Status: %d", exitStatus)
					}
				}
			}
			// return local status, if nonzero;
			// otherwise, return remote status if nonzero
			if exitStatus == 0 {
				exitStatus = uint32(conn.GetStatus())
			}
			log.Printf("*** server->client cp finished, status %d ***\n", conn.GetStatus())
		}
	}
	return
}

// doShellMode begins an hkexsh shell session (one-shot command or interactive).
func doShellMode(isInteractive bool, conn *hkexnet.Conn, oldState *hkexsh.State, rec *hkexsh.Session) {
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
			_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // #nosec
			// Copy operations and user logging off will cause
			// a "use of closed network connection" so handle that
			// gracefully here
			if !strings.HasSuffix(inerr.Error(), "use of closed network connection") {
				log.Println(inerr)
				os.Exit(1)
			}
		}

		rec.SetStatus(uint32(conn.GetStatus()))
		log.Println("rec.status:", rec.Status())

		if isInteractive {
			log.Println("[* Got EOF *]")
			_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // #nosec
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
				_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // #nosec
				log.Println("[Hanging up]")
				os.Exit(0)
			}
		}()
	}

	// Wait until both stdin and stdout goroutines finish before returning
	// (ensure client gets all data from server before closing)
	wg.Wait()
}

func usageShell() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "%s [opts] [user]@server\n", os.Args[0])
	flag.PrintDefaults()
}

func usageCp() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "%s [opts] srcFileOrDir [...] [user]@server[:dstpath]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "%s [opts] [user]@server[:srcFileOrDir] dstPath\n", os.Args[0])
	flag.PrintDefaults()
}

func rejectUserMsg() string {
	return "Begone, " + spinsult.GetSentence() + "\r\n"
}

// Transmit request to server for it to set up the remote end of a tunnel
//
// Server responds with [CSOTunAck:rport] or [CSOTunRefused:rport]
// (handled in hkexnet.Read())
func reqTunnel(hc *hkexnet.Conn, lp uint16, p string /*net.Addr*/, rp uint16) {
	// Write request to server so it can attempt to set up its end
	var bTmp bytes.Buffer
	if e := binary.Write(&bTmp, binary.BigEndian, lp); e != nil {
		fmt.Fprintln(os.Stderr, "reqTunnel:", e)
	}
	if e := binary.Write(&bTmp, binary.BigEndian, rp); e != nil {
		fmt.Fprintln(os.Stderr, "reqTunnel:", e)
	}
	_ = logger.LogDebug(fmt.Sprintln("[Client sending CSOTunSetup]"))
	if n, e := hc.WritePacket(bTmp.Bytes(), hkexnet.CSOTunSetup); e != nil || n != len(bTmp.Bytes()) {
		fmt.Fprintln(os.Stderr, "reqTunnel:", e)
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
				//fmt.Println("remote path isDest")
			}
			//fmt.Println("fancyArgs: user:", fancyUser, "host:", fancyHost, "path:", fancyPath)
		} else {
			otherArgs = append(otherArgs, a[i])
		}
	}
	return fancyUser, fancyHost, fancyPath, isDest, otherArgs
}

func launchTuns(conn *hkexnet.Conn, remoteHost string, tuns string) {
	remAddrs, _ := net.LookupHost(remoteHost)

	if tuns == "" {
		return
	}

	tunSpecs := strings.Split(tuns, ",")
	for _, tunItem := range tunSpecs {
		var lPort, rPort uint16
		_, _ = fmt.Sscanf(tunItem, "%d:%d", &lPort, &rPort)
		reqTunnel(conn, lPort, remAddrs[0], rPort)
	}
}

func sendSessionParams(conn io.Writer /* *hkexnet.Conn*/, rec *hkexsh.Session) (e error) {
	_, e = fmt.Fprintf(conn, "%d %d %d %d %d %d\n",
		len(rec.Op()), len(rec.Who()), len(rec.ConnHost()), len(rec.TermType()), len(rec.Cmd()), len(rec.AuthCookie(true)))
	_, e = conn.Write(rec.Op())
	_, e = conn.Write(rec.Who())
	_, e = conn.Write(rec.ConnHost())
	_, e = conn.Write(rec.TermType())
	_, e = conn.Write(rec.Cmd())
	_, e = conn.Write(rec.AuthCookie(true))
	return
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
	version := hkexsh.Version
	var vopt bool
	var gopt bool //login via password, asking server to generate authToken
	var dbg bool
	var shellMode bool   // if true act as shell, else file copier
	var cipherAlg string //cipher alg
	var hmacAlg string   //hmac alg
	var kexAlg string    //KEX/KEM alg
	var server string
	var port uint
	var cmdStr string
	var tunSpecStr string // lport1:rport1[,lport2:rport2,...]

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
	flag.StringVar(&cipherAlg, "c", "C_AES_256", "`cipher` [\"C_AES_256\" | \"C_TWOFISH_128\" | \"C_BLOWFISH_64\" | \"C_CRYPTMT1\"]")
	flag.StringVar(&hmacAlg, "m", "H_SHA256", "`hmac` [\"H_SHA256\"]")
	flag.StringVar(&kexAlg, "k", "KEX_HERRADURA256", "`kex` [\"KEX_HERRADURA{256/512/1024/2048}\" | \"KEX_KYBER{512/768/1024}\"]")
	flag.UintVar(&port, "p", 2000, "`port`")
	//flag.StringVar(&authCookie, "a", "", "auth cookie")
	flag.BoolVar(&chaffEnabled, "e", true, "enabled chaff pkts (default true)")
	flag.UintVar(&chaffFreqMin, "f", 100, "`msecs-min` chaff pkt freq min (msecs)")
	flag.UintVar(&chaffFreqMax, "F", 5000, "`msecs-max` chaff pkt freq max (msecs)")
	flag.UintVar(&chaffBytesMax, "B", 64, "chaff pkt size max (bytes)")

	// Find out what program we are (shell or copier)
	myPath := strings.Split(os.Args[0], string(os.PathSeparator))
	if myPath[len(myPath)-1] != "hkexcp" && myPath[len(myPath)-1] != "hkexcp.exe" {
		// hkexsh accepts a command (-x) but not
		// a srcpath (-r) or dstpath (-t)
		flag.StringVar(&cmdStr, "x", "", "`command` to run (if not specified run interactive shell)")
		flag.StringVar(&tunSpecStr, "T", "", "`tunnelspec` localPort:remotePort[,localPort:remotePort,...]")
		flag.BoolVar(&gopt, "g", false, "ask server to generate authtoken")
		shellMode = true
		flag.Usage = usageShell
	} else {
		flag.Usage = usageCp
	}
	flag.Parse()

	remoteUser, remoteHost, tmpPath, pathIsDest, otherArgs :=
		parseNonSwitchArgs(flag.Args())
	//fmt.Println("otherArgs:", otherArgs)

	// Set defaults if user doesn't specify user, path or port
	var uname string
	if remoteUser == "" {
		u, _ := user.Current()
		uname = u.Username
	} else {
		uname = remoteUser
	}

	if remoteHost != "" {
		server = remoteHost + ":" + fmt.Sprintf("%d", port)
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

	Log, _ = logger.New(logger.LOG_USER|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR, "hkexsh")
	hkexnet.Init(dbg, "hkexsh", logger.LOG_USER|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR)
	if dbg {
		log.SetOutput(Log)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	if !gopt {
		// See if we can log in via an auth token
		u, _ := user.Current()
		ab, aerr := ioutil.ReadFile(fmt.Sprintf("%s/.hkexsh_id", u.HomeDir))
		if aerr == nil {
			idx := strings.Index(string(ab), remoteHost)
			if idx >= 0 {
				ab = ab[idx:]
				entries := strings.SplitN(string(ab), "\n", -1)
				authCookie = strings.TrimSpace(entries[0])
				// Security scrub
				ab = nil
				runtime.GC()
			} else {
				_, _ = fmt.Fprintln(os.Stderr, "[no authtoken, use -g to request one from server]")
			}
		} else {
			log.Printf("[cannot read %s/.hkexsh_id]\n", u.HomeDir)
		}
	}

	if shellMode {
		// We must make the decision about interactivity before Dial()
		// as it affects chaffing behaviour. 20180805
		if gopt {
			fmt.Fprintln(os.Stderr, "[requesting authtoken from server]")
			op = []byte{'A'}
			chaffFreqMin = 2
			chaffFreqMax = 10
		} else if len(cmdStr) == 0 {
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
			//fmt.Println("client->server copy:", string(copySrc), "->", copyDst)
			cmdStr = copyDst
		} else {
			// server->client file copy
			// remote src file(s) in copyDsr
			op = []byte{'S'}
			//fmt.Println("server->client copy:", string(copySrc), "->", copyDst)
			cmdStr = string(copySrc)
		}
	}

	conn, err := hkexnet.Dial("tcp", server, cipherAlg, hmacAlg, kexAlg)
	if err != nil {
		fmt.Println(err)
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
		//No auth token, prompt for password
		fmt.Printf("Gimme cookie:")
		ab, e := hkexsh.ReadPassword(int(os.Stdin.Fd()))
		fmt.Printf("\r\n")
		if e != nil {
			panic(e)
		}
		authCookie = string(ab)
	}
	// Security scrub
	runtime.GC()

	// Set up session params and send over to server
	rec := hkexsh.NewSession(op, []byte(uname), []byte(remoteHost), []byte(os.Getenv("TERM")), []byte(cmdStr), []byte(authCookie), 0)
	sendSessionParams(&conn, rec)

	//Security scrub
	authCookie = ""
	runtime.GC()

	// Read auth reply from server
	authReply := make([]byte, 1) // bool: 0 = fail, 1 = pass
	_, err = conn.Read(authReply)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading auth reply")
		rec.SetStatus(255)
	} else if authReply[0] == 0 {
		fmt.Fprintln(os.Stderr, rejectUserMsg())
		rec.SetStatus(255)
	} else {

		// Set up chaffing to server
		conn.SetupChaff(chaffFreqMin, chaffFreqMax, chaffBytesMax) // enable client->server chaffing
		if chaffEnabled {
			conn.EnableChaff() // goroutine, returns immediately
			defer conn.DisableChaff()
			defer conn.ShutdownChaff()
		}

		// Keepalive for any tunnels that may exist
		go func() {
			for {
				time.Sleep(time.Duration(2) * time.Second)
				conn.WritePacket([]byte{0, 0}, hkexnet.CSOTunKeepAlive)
			}
		}()

		if shellMode {
			launchTuns(&conn, remoteHost, tunSpecStr)

			doShellMode(isInteractive, &conn, oldState, rec)
		} else { // copyMode
			s, _ := doCopyMode(&conn, pathIsDest, fileArgs, rec)
			rec.SetStatus(s)
		}

		if rec.Status() != 0 {
			fmt.Fprintln(os.Stderr, "Session exited with status:", rec.Status())
		}
	}

	if oldState != nil {
		_ = hkexsh.Restore(int(os.Stdin.Fd()), oldState) // Best effort.
	}
	os.Exit(int(rec.Status()))
}
