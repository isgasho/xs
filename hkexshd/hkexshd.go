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
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strings"
	"sync"
	"syscall"

	"blitter.com/go/goutmp"
	hkexsh "blitter.com/go/hkexsh"
	"blitter.com/go/hkexsh/hkexnet"
	"github.com/kr/pty"
)

/* -------------------------------------------------------------- */
// Perform a client->server copy
func runClientToServerCopyAs(who, ttype string, conn hkexnet.Conn, fpath string, chaffing bool) (err error, exitStatus uint32) {
	u, _ := user.Lookup(who)
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	os.Setenv("HOME", u.HomeDir)
	os.Setenv("TERM", ttype)

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
	c = exec.Command(cmdName, cmdArgs...)

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
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		return err, hkexnet.CSEExecFail // !?
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
					log.Printf("Exit Status: %d", exitStatus)
				}
			}
		}
		//fmt.Println("*** client->server cp finished ***")
		return
	}
}

// Perform a server->client copy
func runServerToClientCopyAs(who, ttype string, conn hkexnet.Conn, srcPath string, chaffing bool) (err error, exitStatus uint32) {
	u, _ := user.Lookup(who)
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	os.Setenv("HOME", u.HomeDir)
	os.Setenv("TERM", ttype)

	var c *exec.Cmd
	cmdName := "/bin/tar"
	if !path.IsAbs(srcPath) {
		srcPath = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, srcPath)
	}

	srcDir, srcBase := path.Split(srcPath)
	cmdArgs := []string{"-cz", "-C", srcDir, "-f", "-", srcBase}

	c = exec.Command(cmdName, cmdArgs...)

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
		return err, hkexnet.CSEExecFail // !?
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
}

// Run a command (via default shell) as a specific user
//
// Uses ptys to support commands which expect a terminal.
func runShellAs(who, ttype string, cmd string, interactive bool, conn hkexnet.Conn, chaffing bool) (err error, exitStatus uint32) {
	var wg sync.WaitGroup
	u, _ := user.Lookup(who)
	var uid, gid uint32
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	log.Println("uid:", uid, "gid:", gid)

	// Need to clear server's env and set key vars of the
	// target user. This isn't perfect (TERM doesn't seem to
	// work 100%; ANSI/xterm colour isn't working even
	// if we set "xterm" or "ansi" here; and line count
	// reported by 'stty -a' defaults to 24 regardless
	// of client shell window used to run client.
	// Investigate -- rlm 2018-01-26)
	os.Clearenv()
	os.Setenv("HOME", u.HomeDir)
	os.Setenv("TERM", ttype)

	var c *exec.Cmd
	if interactive {
		c = exec.Command("/bin/bash", "-i", "-l")
	} else {
		c = exec.Command("/bin/bash", "-c", cmd)
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
		return err, hkexnet.CSEPtyExecFail
	}
	// Make sure to close the pty at the end.
	defer func() { _ = ptmx.Close() }() // Best effort.

	log.Printf("[%s]\n", cmd)
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	} else {

		// Watch for term resizes
		go func() {
			for sz := range conn.WinCh {
				log.Printf("[Setting term size to: %v %v]\n", sz.Rows, sz.Cols)
				pty.Setsize(ptmx, &pty.Winsize{Rows: sz.Rows, Cols: sz.Cols})
			}
			fmt.Println("*** WinCh goroutine done ***")
		}()

		// Copy stdin to the pty.. (bgnd goroutine)
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
		defer conn.DisableChaff()
		defer conn.ShutdownChaff()

		// ..and the pty to stdout.
		// This may take some time exceeding that of the
		// actual command's lifetime, so the c.Wait() below
		// must synchronize with the completion of this goroutine
		// to ensure all stdout data gets to the client before
		// connection is closed.
		wg.Add(1)
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
			conn.SetStatus(exitStatus)
		}
		wg.Wait() // Wait on pty->stdout completion to client
	}
	return
}

// Demo of a simple server that listens and spawns goroutines for each
// connecting client. Note this code is identical to standard tcp
// server code, save for declaring 'hkex' rather than 'net'
// Listener and Conns. The KEx and encrypt/decrypt is done within the type.
// Compare to 'serverp.go' in this directory to see the equivalence.
func main() {
	version := "0.1pre (NO WARRANTY)"
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

	if dbg {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := hkexnet.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Println("Serving on", laddr)
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept() got error(%v), hanging up.\n", err)
			conn.Close()
			//log.Fatal(err)
		} else {
			log.Println("Accepted client")

			// Set up chaffing to client
			// Will only start when runShellAs() is called
			// after stdin/stdout are hooked up
			conn.SetupChaff(chaffFreqMin, chaffFreqMax, chaffBytesMax) // configure server->client chaffing

			// Handle the connection in a new goroutine.
			// The loop then returns to accepting, so that
			// multiple connections may be served concurrently.
			go func(hc hkexnet.Conn) (e error) {
				defer hc.Close()

				//We use io.ReadFull() here to guarantee we consume
				//just the data we want for the hkexsh.Session, and no more.
				//Otherwise data will be sitting in the channel that isn't
				//passed down to the command handlers.
				var rec hkexsh.Session
				var len1, len2, len3, len4, len5 uint32

				n, err := fmt.Fscanf(hc, "%d %d %d %d %d\n", &len1, &len2, &len3, &len4, &len5)
				log.Printf("hkexsh.Session read:%d %d %d %d %d\n", len1, len2, len3, len4, len5)

				if err != nil || n < 5 {
					log.Println("[Bad hkexsh.Session fmt]")
					return err
				}
				//fmt.Printf("  lens:%d %d %d %d %d\n", len1, len2, len3, len4, len5)

				tmp := make([]byte, len1, len1)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.Op]")
					return err
				}
				rec.SetOp(tmp)

				tmp = make([]byte, len2, len2)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.Who]")
					return err
				}
				rec.SetWho(tmp)

				tmp = make([]byte, len3, len3)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.TermType]")
					return err
				}
				rec.SetTermType(tmp)

				tmp = make([]byte, len4, len4)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.Cmd]")
					return err
				}
				rec.SetCmd(tmp)

				tmp = make([]byte, len5, len5)
				_, err = io.ReadFull(hc, tmp)
				if err != nil {
					log.Println("[Bad hkexsh.Session.AuthCookie]")
					return err
				}
				rec.SetAuthCookie(tmp)

				log.Printf("[hkexsh.Session: op:%c who:%s cmd:%s auth:****]\n",
					rec.Op()[0], string(rec.Who()), string(rec.Cmd()))

				valid, allowedCmds := hkexsh.AuthUser(string(rec.Who()), string(rec.AuthCookie(true)), "/etc/hkexsh.passwd")

				// Security scrub
				rec.ClearAuthCookie()

				// Tell client if auth was valid
				if valid {
					hc.Write([]byte{1})
				} else {
					log.Println("Invalid user", string(rec.Who()))
					hc.Write([]byte{0}) // ? required?
					return
				}

				log.Printf("[allowedCmds:%s]\n", allowedCmds)

				if rec.Op()[0] == 'c' {
					// Non-interactive command
					addr := hc.RemoteAddr()
					//hname := goutmp.GetHost(addr.String())
					hname := strings.Split(addr.String(), ":")[0]

					log.Printf("[Running command for [%s@%s]]\n", rec.Who(), hname)
					runErr, cmdStatus := runShellAs(string(rec.Who()), string(rec.TermType()), string(rec.Cmd()), false, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						log.Printf("[Error spawning cmd for %s@%s]\n", rec.Who, hname)
					} else {
						log.Printf("[Command completed for %s@%s, status %d]\n", rec.Who, hname, cmdStatus)
						hc.SetStatus(cmdStatus)
					}
				} else if rec.Op()[0] == 's' {
					// Interactive session
					addr := hc.RemoteAddr()
					//hname := goutmp.GetHost(addr.String())
					hname := strings.Split(addr.String(), ":")[0]
					log.Printf("[Running shell for [%s@%s]]\n", rec.Who(), hname)

					utmpx := goutmp.Put_utmp(string(rec.Who()), hname)
					defer func() { goutmp.Unput_utmp(utmpx) }()
					goutmp.Put_lastlog_entry("hkexsh", string(rec.Who()), hname)
					runErr, cmdStatus := runShellAs(string(rec.Who()), string(rec.TermType()), string(rec.Cmd()), true, hc, chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						log.Printf("[Error spawning shell for %s@%s]\n", rec.Who(), hname)
					} else {
						log.Printf("[Shell completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)
						hc.SetStatus(cmdStatus)
					}
				} else if rec.Op()[0] == 'D' {
					// File copy (destination) operation - client copy to server
					log.Printf("[Client->Server copy]\n")
					addr := hc.RemoteAddr()
					hname := strings.Split(addr.String(), ":")[0]
					log.Printf("[Running copy for [%s@%s]]\n", rec.Who(), hname)
					runErr, cmdStatus := runClientToServerCopyAs(string(rec.Who()), string(rec.TermType()), hc, string(rec.Cmd()), chaffEnabled)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						log.Printf("[Error spawning cp for %s@%s]\n", rec.Who(), hname)
					} else {
						log.Printf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)
					}
					hc.SetStatus(cmdStatus)
				} else if rec.Op()[0] == 'S' {
					// File copy (src) operation - server copy to client
					log.Printf("[Server->Client copy]\n")
					addr := hc.RemoteAddr()
					hname := strings.Split(addr.String(), ":")[0]
					log.Printf("[Running copy for [%s@%s]]\n", rec.Who(), hname)
					runErr, cmdStatus := runServerToClientCopyAs(string(rec.Who()), string(rec.TermType()), hc, string(rec.Cmd()), chaffEnabled)
					//fmt.Print("ServerToClient cmdStatus:", cmdStatus)
					// Returned hopefully via an EOF or exit/logout;
					// Clear current op so user can enter next, or EOF
					rec.SetOp([]byte{0})
					if runErr != nil {
						log.Printf("[Error spawning cp for %s@%s]\n", rec.Who(), hname)
					} else {
						log.Printf("[Command completed for %s@%s, status %d]\n", rec.Who(), hname, cmdStatus)
					}
					hc.SetStatus(cmdStatus)
					// Signal other end transfer is complete
					s := make([]byte, 4)
					binary.BigEndian.PutUint32(s, cmdStatus)
					hc.WritePacket(s, hkexnet.CSOExitStatus)
					//fmt.Println("Waiting for EOF from other end.")
					_, _ = hc.Read(nil /*ackByte*/)
					//fmt.Println("Got remote end ack.")
				} else {
					log.Println("[Bad hkexsh.Session]")
				}
				return
			}(conn)
		} // Accept() success
	} //endfor
	log.Println("[Exiting]")
}
