// hkexshd server
//
// Copyright (c) 2017-2018 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"sync"
	"syscall"

	"blitter.com/go/goutmp"
	hkexsh "blitter.com/go/hkexsh"
	"blitter.com/go/hkexsh/hkexnet"
	"blitter.com/go/hkexsh/logger"
	"github.com/kr/pty"
)

var (
	// Log - syslog output (with no -d)
	Log *logger.Writer
)

/* -------------------------------------------------------------- */
// Perform a client->server copy
func runClientToServerCopyAs(who, ttype string, conn *hkexnet.Conn, fpath string, chaffing bool) (exitStatus uint32, err error) {
	u, _ := user.Lookup(who) // nolint: gosec
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid) // nolint: gosec,errcheck
	fmt.Sscanf(u.Gid, "%d", &gid) // nolint: gosec,errcheck
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	os.Setenv("HOME", u.HomeDir) // nolint: gosec,errcheck
	os.Setenv("TERM", ttype) // nolint: gosec,errcheck
	os.Setenv("HKEXSH", "1") // nolint: gosec,errcheck

	var c *exec.Cmd
	cmdName := "/bin/tar"

	var destDir string
	if path.IsAbs(fpath) {
		destDir = fpath
	} else {
		destDir = path.Join(u.HomeDir, fpath)
	}

	cmdArgs := []string{"-xz", "-C", destDir}

	// NOTE the lack of quotes around --xform option's sed expression.
	// When args are passed in exec() format, no quoting is required
	// (as this isn't input from a shell) (right? -rlm 20180823)
	//cmdArgs := []string{"-x", "-C", destDir, `--xform=s#.*/\(.*\)#\1#`}
	c = exec.Command(cmdName, cmdArgs...) // nolint: gosec

	c.Dir = destDir

	//If os.Clearenv() isn't called by server above these will be seen in the
	//client's session env.
	//c.Env = []string{"HOME=" + u.HomeDir, "SUDO_GID=", "SUDO_UID=", "SUDO_USER=", "SUDO_COMMAND=", "MAIL=", "LOGNAME="+who}
	//c.Dir = u.HomeDir
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	c.Stdin = conn
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if chaffing {
		conn.EnableChaff()
	}
	defer conn.DisableChaff()
	defer conn.ShutdownChaff()

	// Start the command (no pty)
	log.Printf("[%v %v]\n", cmdName, cmdArgs)
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
		log.Println("cmd exited immediately. Cannot get cmd.Wait().ExitStatus()")
		err = errors.New("cmd exited prematurely")
		//exitStatus = uint32(254)
		exitStatus = hkexnet.CSEExecFail
	} else {
		if err := c.Wait(); err != nil {
			//fmt.Println("*** c.Wait() done ***")
			if exiterr, ok := err.(*exec.ExitError); ok {
				// The program has exited with an exit code != 0

				// This works on both Unix and Windows. Although package
				// syscall is generally platform dependent, WaitStatus is
				// defined for both Unix and Windows and in both cases has
				// an ExitStatus() method with the same signature.
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					exitStatus = uint32(status.ExitStatus())
					//err = errors.New("cmd returned nonzero status")
					log.Printf("Exit Status: %d\n", exitStatus)
				}
			}
		}
		log.Println("*** client->server cp finished ***")
	}
	return
}

// Perform a server->client copy
func runServerToClientCopyAs(who, ttype string, conn *hkexnet.Conn, srcPath string, chaffing bool) (exitStatus uint32, err error) {
	u, err := user.Lookup(who)
	if err != nil {
		exitStatus = 1
		return
	}
	var uid, gid uint32
	_, _ = fmt.Sscanf(u.Uid, "%d", &uid) // nolint: gosec
	_, _ = fmt.Sscanf(u.Gid, "%d", &gid) // nolint: gosec
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	_ = os.Setenv("HOME", u.HomeDir) // nolint: gosec
	_ = os.Setenv("TERM", ttype)     // nolint: gosec
	_ = os.Setenv("HKEXSH", "1")     // nolint: gosec

	var c *exec.Cmd
	cmdName := "/bin/tar"
	if !path.IsAbs(srcPath) {
		srcPath = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, srcPath)
	}

	srcDir, srcBase := path.Split(srcPath)
	cmdArgs := []string{"-cz", "-C", srcDir, "-f", "-", srcBase}

	c = exec.Command(cmdName, cmdArgs...) // nolint: gosec

	//If os.Clearenv() isn't called by server above these will be seen in the
	//client's session env.
	//c.Env = []string{"HOME=" + u.HomeDir, "SUDO_GID=", "SUDO_UID=", "SUDO_USER=", "SUDO_COMMAND=", "MAIL=", "LOGNAME="+who}
	c.Dir = u.HomeDir
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	c.Stdout = conn
	// Stderr sinkholing (or buffering to something other than stdout)
	// is important. Any extraneous output to tarpipe messes up remote
	// side as it's expecting pure tar data.
	// (For example, if user specifies abs paths, tar outputs
	// "Removing leading '/' from path names")
	stdErrBuffer := new(bytes.Buffer)
	c.Stderr = stdErrBuffer
	//c.Stderr = nil

	if chaffing {
		conn.EnableChaff()
	}
	//defer conn.Close()
	defer conn.DisableChaff()
	defer conn.ShutdownChaff()

	// Start the command (no pty)
	log.Printf("[%v %v]\n", cmdName, cmdArgs)
	err = c.Start() // returns immediately
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		return hkexnet.CSEExecFail, err // !?
	}
	if err := c.Wait(); err != nil {
		//fmt.Println("*** c.Wait() done ***")
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				exitStatus = uint32(status.ExitStatus())
				if len(stdErrBuffer.Bytes()) > 0 {
					log.Print(stdErrBuffer)
				}
				log.Printf("Exit Status: %d", exitStatus)
			}
		}
	}
	//fmt.Println("*** server->client cp finished ***")
	return
}

// Run a command (via default shell) as a specific user
//
// Uses ptys to support commands which expect a terminal.
// nolint: gocyclo
func runShellAs(who, ttype string, cmd string, interactive bool, conn *hkexnet.Conn, chaffing bool) (exitStatus uint32, err error) {
	var wg sync.WaitGroup
	u, err := user.Lookup(who)
	if err != nil {
		exitStatus = 1
		return
	}
	var uid, gid uint32
	_, _ = fmt.Sscanf(u.Uid, "%d", &uid) // nolint: gosec
	_, _ = fmt.Sscanf(u.Gid, "%d", &gid) // nolint: gosec
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	_ = os.Setenv("HOME", u.HomeDir) // nolint: gosec
	_ = os.Setenv("TERM", ttype)     // nolint: gosec
	_ = os.Setenv("HKEXSH", "1")     // nolint: gosec

	var c *exec.Cmd
	if interactive {
		c = exec.Command("/bin/bash", "-i", "-l") // nolint: gosec
	} else {
		c = exec.Command("/bin/bash", "-c", cmd) // nolint: gosec
	}
	//If os.Clearenv() isn't called by server above these will be seen in the
	//client's session env.
	//c.Env = []string{"HOME=" + u.HomeDir, "SUDO_GID=", "SUDO_UID=", "SUDO_USER=", "SUDO_COMMAND=", "MAIL=", "LOGNAME="+who}
	c.Dir = u.HomeDir
	c.SysProcAttr = &syscall.SysProcAttr{}
	c.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	c.Stdin = conn
	c.Stdout = conn
	c.Stderr = conn

	// Start the command with a pty.
	ptmx, err := pty.Start(c) // returns immediately with ptmx file
	if err != nil {
		return hkexnet.CSEPtyExecFail, err
	}
	// Make sure to close the pty at the end.
	// #gv:s/label=\"runShellAs\$1\"/label=\"deferPtmxClose\"/
	defer func() { _ = ptmx.Close() }() // nolint: gosec

	log.Printf("[%s]\n", cmd)
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	} else {
		// Watch for term resizes
		// #gv:s/label=\"runShellAs\$2\"/label=\"termResizeWatcher\"/
		go func() {
			for sz := range conn.WinCh {
				log.Printf("[Setting term size to: %v %v]\n", sz.Rows, sz.Cols)
				pty.Setsize(ptmx, &pty.Winsize{Rows: sz.Rows, Cols: sz.Cols}) // nolint: gosec,errcheck
			}
			log.Println("*** WinCh goroutine done ***")
		}()

		// Copy stdin to the pty.. (bgnd goroutine)
		// #gv:s/label=\"runShellAs\$3\"/label=\"stdinToPtyWorker\"/
		go func() {
			_, e := io.Copy(ptmx, conn)
			if e != nil {
				log.Println("** stdin->pty ended **:", e.Error())
			} else {
				log.Println("*** stdin->pty goroutine done ***")
			}
		}()

		if chaffing {
			conn.EnableChaff()
		}
		// #gv:s/label=\"runShellAs\$4\"/label=\"deferChaffShutdown\"/
		defer func() {
				conn.DisableChaff()
				conn.ShutdownChaff()
		}()
		

		// ..and the pty to stdout.
		// This may take some time exceeding that of the
		// actual command's lifetime, so the c.Wait() below
		// must synchronize with the completion of this goroutine
		// to ensure all stdout data gets to the client before
		// connection is closed.
		wg.Add(1)
		// #gv:s/label=\"runShellAs\$5\"/label=\"ptyToStdoutWorker\"/
		go func() {
			defer wg.Done()
			_, e := io.Copy(conn, ptmx)
			if e != nil {
				log.Println("** pty->stdout ended **:", e.Error())
			} else {
				// The above io.Copy() will exit when the command attached
				// to the pty exits
				log.Println("*** pty->stdout goroutine done ***")
			}
		}()

		if err := c.Wait(); err != nil {
			//fmt.Println("*** c.Wait() done ***")
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
			conn.SetStatus(hkexnet.CSOType(exitStatus))
		}
		wg.Wait() // Wait on pty->stdout completion to client
	}
	return
}

// GenAuthToken generates a pseudorandom auth token for a specific
// user from a specific host to allow non-interactive logins.
func GenAuthToken(who string, connhost string) string {
	//tokenA, e := os.Hostname()
	//if e != nil {
	//	tokenA = "badhost"
	//}
	tokenA := connhost

	tokenB := make([]byte, 64)
	_, _ = rand.Read(tokenB) // nolint: gosec
	return fmt.Sprintf("%s:%s", tokenA, hex.EncodeToString(tokenB))
}

// Demo of a simple server that listens and spawns goroutines for each
// connecting client. Note this code is identical to standard tcp
// server code, save for declaring 'hkex' rather than 'net'
// Listener and Conns. The KEx and encrypt/decrypt is done within the type.
// Compare to 'serverp.go' in this directory to see the equivalence.
// TODO: reduce gocyclo
func main() {
	version := hkexsh.Version

	var vopt bool
	var chaffEnabled bool
	var chaffFreqMin uint
	var chaffFreqMax uint
	var chaffBytesMax uint
	var dbg bool
	var laddr string

	flag.BoolVar(&vopt, "v", false, "show version")
	flag.StringVar(&laddr, "l", ":2000", "interface[:port] to listen")
	flag.BoolVar(&chaffEnabled, "e", true, "enabled chaff pkts")
	flag.UintVar(&chaffFreqMin, "f", 100, "chaff pkt freq min (msecs)")
	flag.UintVar(&chaffFreqMax, "F", 5000, "chaff pkt freq max (msecs)")
	flag.UintVar(&chaffBytesMax, "B", 64, "chaff pkt size max (bytes)")
	flag.BoolVar(&dbg, "d", false, "debug logging")
	flag.Parse()

	if vopt {
		fmt.Printf("version v%s\n", version)
		os.Exit(0)
	}

	{
		me, e := user.Current()
		if e != nil || me.Uid != "0" {
			log.Fatal("Must run as root.")
		}
	}

	Log, _ = logger.New(logger.LOG_DAEMON|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR, "hkexshd") // nolint: gosec
	hkexnet.Init(dbg, "hkexshd", logger.LOG_DAEMON|logger.LOG_DEBUG|logger.LOG_NOTICE|logger.LOG_ERR)
	if dbg {
		log.SetOutput(Log)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	// Set up handler for daemon signalling
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, os.Signal(syscall.SIGTERM), os.Signal(syscall.SIGINT), os.Signal(syscall.SIGHUP), os.Signal(syscall.SIGUSR1), os.Signal(syscall.SIGUSR2))
	go func() {
		for {
			sig := <-exitCh
			switch sig.String() {
			case "terminated":
				logger.LogNotice(fmt.Sprintf("[Got signal: %s]", sig)) // nolint: gosec,errcheck
				signal.Reset()
				syscall.Kill(0, syscall.SIGTERM) // nolint: gosec,errcheck
			case "interrupt":
				logger.LogNotice(fmt.Sprintf("[Got signal: %s]", sig)) // nolint: gosec,errcheck
				signal.Reset()
				syscall.Kill(0, syscall.SIGINT) // nolint: gosec,errcheck
			case "hangup":
				logger.LogNotice(fmt.Sprintf("[Got signal: %s - nop]", sig)) // nolint:gosec,errcheck
			default:
				logger.LogNotice(fmt.Sprintf("[Got signal: %s - ignored]", sig)) // nolint: gosec,errcheck
			}
		}
	}()

	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := hkexnet.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close() // nolint: errcheck

	log.Println("Serving on", laddr)
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept() got error(%v), hanging up.\n", err)
		} else {
			log.Println("Accepted client")

			// Set up chaffing to client
			// Will only start when runShellAs() is called
			// after stdin/stdout are hooked up
			conn.SetupChaff(chaffFreqMin, chaffFreqMax, chaffBytesMax) // configure server->client chaffing

			// Handle the connection in a new goroutine.
			// The loop then returns to accepting, so that
			// multiple connections may be served concurrently.
			go func(hc *hkexnet.Conn) (e error) {
				defer hc.Close() // nolint: errcheck

				//We use io.ReadFull() here to guarantee we consume
				//just the data we want for the hkexsh.Session, and no more.
				//Otherwise data will be sitting in the channel that isn't
				//passed down to the command handlers.
				var rec hkexsh.Session
				var len1, len2, len3, len4, len5, len6 uint32

				n, err := fmt.Fscanf(hc, "%d %d %d %d %d %d\n", &len1, &len2, &len3, &len4, &len5, &len6)
				log.Printf("hkexsh.Session read:%d %d %d %d %d %d\n", len1, len2, len3, len4, len5, len6)

				if err != nil || n < 6 {
					log.Println("[Bad hkexsh.Session fmt]")
					return err
				}

				tmp := make([]byte, len1)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.Op]")
					return err
				}
				rec.SetOp(tmp)

				tmp = make([]byte, len2)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.Who]")
					return err
				}
				rec.SetWho(tmp)

				tmp = make([]byte, len3)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.ConnHost]")
					return err
				}
				rec.SetConnHost(tmp)

				tmp = make([]byte, len4)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.TermType]")
					return err
				}
				rec.SetTermType(tmp)

				tmp = make([]byte, len5)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.Cmd]")
					return err
				}
				rec.SetCmd(tmp)

				tmp = make([]byte, len6)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.AuthCookie]")
					return err
				}
				rec.SetAuthCookie(tmp)

				log.Printf("[hkexsh.Session: op:%c who:%s connhost:%s cmd:%s auth:****]\n",
					rec.Op()[0], string(rec.Who()), string(rec.ConnHost()), string(rec.Cmd()))

				var valid bool
				var allowedCmds string // Currently unused
				if hkexsh.AuthUserByToken(string(rec.Who()), string(rec.ConnHost()), string(rec.AuthCookie(true))) {
					valid = true
				} else {
					valid, allowedCmds = hkexsh.AuthUserByPasswd(string(rec.Who()), string(rec.AuthCookie(true)), "/etc/hkexsh.passwd")
				}

				// Security scrub
				rec.ClearAuthCookie()

				// Tell client if auth was valid
				if valid {
					hc.Write([]byte{1}) // nolint: gosec,errcheck
				} else {
					logger.LogNotice(fmt.Sprintln("Invalid user", string(rec.Who()))) // nolint: errcheck,gosec
					hc.Write([]byte{0}) // nolint: gosec,errcheck
					return
				}

				log.Printf("[allowedCmds:%s]\n", allowedCmds)

				if rec.Op()[0] == 'A' {
					// Generate automated login token
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Generating autologin token for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					token := GenAuthToken(string(rec.Who()), string(rec.ConnHost()))
					tokenCmd := fmt.Sprintf("echo \"%s\" | tee -a ~/.hkexsh_id", token)
					cmdStatus, runErr := runShellAs(string(rec.Who()), string(rec.TermType()), tokenCmd, false, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error generating autologin token for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						log.Printf("[Autologin token generation completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)
						hc.SetStatus(hkexnet.CSOType(cmdStatus))
					}
				} else if rec.Op()[0] == 'c' {
					// Non-interactive command
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running command for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					cmdStatus, runErr := runShellAs(string(rec.Who()), string(rec.TermType()), string(rec.Cmd()), false, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error spawning cmd for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						logger.LogNotice(fmt.Sprintf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
						hc.SetStatus(hkexnet.CSOType(cmdStatus))
					}
				} else if rec.Op()[0] == 's' {
					// Interactive session
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running shell for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck

					utmpx := goutmp.Put_utmp(string(rec.Who()), hname)
					defer func() { goutmp.Unput_utmp(utmpx) }()
					goutmp.Put_lastlog_entry("hkexsh", string(rec.Who()), hname)
					cmdStatus, runErr := runShellAs(string(rec.Who()), string(rec.TermType()), string(rec.Cmd()), true, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						Log.Err(fmt.Sprintf("[Error spawning shell for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						logger.LogNotice(fmt.Sprintf("[Shell completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
						hc.SetStatus(hkexnet.CSOType(cmdStatus))
					}
				} else if rec.Op()[0] == 'D' {
					// File copy (destination) operation - client copy to server
					log.Printf("[Client->Server copy]\n")
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running copy for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					cmdStatus, runErr := runClientToServerCopyAs(string(rec.Who()), string(rec.TermType()), hc, string(rec.Cmd()), chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error running cp for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						logger.LogNotice(fmt.Sprintf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
					}
					hc.SetStatus(hkexnet.CSOType(cmdStatus))

					// Send CSOExitStatus *before* client closes channel
					s := make([]byte, 4)
					binary.BigEndian.PutUint32(s, cmdStatus)
					log.Printf("** cp writing closeStat %d at Close()\n", cmdStatus)
					hc.WritePacket(s, hkexnet.CSOExitStatus) // nolint: gosec,errcheck
				} else if rec.Op()[0] == 'S' {
					// File copy (src) operation - server copy to client
					log.Printf("[Server->Client copy]\n")
					addr := hc.RemoteAddr()
					hname := goutmp.GetHost(addr.String())
					logger.LogNotice(fmt.Sprintf("[Running copy for [%s@%s]]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					cmdStatus, runErr := runServerToClientCopyAs(string(rec.Who()), string(rec.TermType()), hc, string(rec.Cmd()), chaffEnabled)
					if runErr != nil {
						logger.LogErr(fmt.Sprintf("[Error spawning cp for %s@%s]\n", rec.Who(), hname)) // nolint: gosec,errcheck
					} else {
						// Returned hopefully via an EOF or exit/logout;
						logger.LogNotice(fmt.Sprintf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)) // nolint: gosec,errcheck
					}
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					hc.SetStatus(hkexnet.CSOType(cmdStatus))
					//fmt.Println("Waiting for EOF from other end.")
					//_, _ = hc.Read(nil /*ackByte*/)
					//fmt.Println("Got remote end ack.")
				} else {
					logger.LogErr(fmt.Sprintln("[Bad hkexsh.Session]")) // nolint: gosec,errcheck
				}
				return
			}(&conn) // nolint: errcheck
		} // Accept() success
	} //endfor
	//logger.LogNotice(fmt.Sprintln("[Exiting]")) // nolint: gosec,errcheck
}
